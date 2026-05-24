/*
 * pam_vpnmfa.c — IAA-VPN PAM orchestrator module
 *
 * This module is loaded by the IdP via PAM service "iaa-vpn". The IdP calls
 * pam_authenticate(); this module then:
 *
 *   1. Reads PAM_USER and PAM_RHOST.
 *   2. Reads the custom PAM env var IAA_RISK_SCORE (0–100) set by the bridge.
 *   3. Maps the score to a tier:
 *        L1 (score <  THRESHOLD_LOW)  → password
 *        L2 (score <  THRESHOLD_MED)  → password + TOTP
 *        L3 (otherwise)               → password + TOTP + FIDO2
 *   4. For each required factor, sends a PAM_PROMPT_ECHO_OFF message of the
 *      form "FACTOR:<name>" through the conversation function. The Python
 *      bridge replies with "OK" / "FAIL" / "UNAVAILABLE".
 *   5. Returns PAM_SUCCESS, PAM_AUTH_ERR, or PAM_AUTHINFO_UNAVAIL.
 *
 * The module does no HTTP, no JSON parsing, and links only against libpam.
 * Build with:
 *     gcc -Wall -Wextra -fPIC -shared -O2 -o pam_vpnmfa.so pam_vpnmfa.c -lpam
 *
 * The matching PAM service profile lives in pam.d/iaa-vpn.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>

/* Risk tier thresholds (§1.4 — must match idp/rba.py).
 * rba.py returns a 0-100 score (see §2.7), THRESHOLD_LOW = 30, MED = 60. */
#define THRESHOLD_LOW   30
#define THRESHOLD_MED   60

#define MAX_FACTORS     8
#define MAX_RESP_LEN    32

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static int read_score(pam_handle_t *pamh)
{
    const char *score_env = pam_getenv(pamh, "IAA_RISK_SCORE");
    if (!score_env || !*score_env) {
        syslog(LOG_AUTH | LOG_WARNING,
               "pam_vpnmfa: IAA_RISK_SCORE not set, defaulting to 100 (HIGH)");
        return 100;
    }
    int score = atoi(score_env);
    if (score < 0)   score = 0;
    if (score > 100) score = 100;
    return score;
}

static const char *tier_label(int score)
{
    if (score < THRESHOLD_LOW) return "L1";
    if (score < THRESHOLD_MED) return "L2";
    return "L3";
}

/* Fill `out` with the factor names required at this score. Returns count. */
static int required_factors(int score, const char *out[MAX_FACTORS])
{
    int n = 0;
    out[n++] = "password";
    if (score >= THRESHOLD_LOW) out[n++] = "totp";
    if (score >= THRESHOLD_MED) out[n++] = "fido2";
    return n;
}

/* Send a single conv message; copy the response (NUL-terminated) into `resp`.
 * Returns PAM_SUCCESS on success, an error code otherwise. */
static int ask(pam_handle_t *pamh, int style, const char *prompt,
               char *resp, size_t resp_len)
{
    const struct pam_conv *conv = NULL;
    int rc = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (rc != PAM_SUCCESS || !conv || !conv->conv) {
        return PAM_CONV_ERR;
    }

    struct pam_message  msg   = { .msg_style = style, .msg = prompt };
    struct pam_message *msgp  = &msg;
    struct pam_response *r    = NULL;

    rc = conv->conv(1, (const struct pam_message **)&msgp, &r, conv->appdata_ptr);
    if (rc != PAM_SUCCESS || !r) {
        if (r) free(r);
        return PAM_CONV_ERR;
    }

    if (resp && resp_len > 0) {
        resp[0] = '\0';
        if (r[0].resp) {
            strncpy(resp, r[0].resp, resp_len - 1);
            resp[resp_len - 1] = '\0';
        }
    }

    if (r[0].resp) free(r[0].resp);
    free(r);
    return PAM_SUCCESS;
}

/* Informational message — bridge stashes it for logging, no useful response. */
static void info(pam_handle_t *pamh, const char *text)
{
    char dummy[8];
    ask(pamh, PAM_TEXT_INFO, text, dummy, sizeof(dummy));
}

/* ── Module entry points ─────────────────────────────────────────────────── */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;

    const char *user  = NULL;
    const char *rhost = NULL;

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) {
        syslog(LOG_AUTH | LOG_ERR, "pam_vpnmfa: cannot get user");
        return PAM_AUTH_ERR;
    }
    pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);

    int score = read_score(pamh);
    const char *tier = tier_label(score);

    syslog(LOG_AUTH | LOG_INFO,
           "pam_vpnmfa: user=%s rhost=%s score=%d tier=%s",
           user, rhost ? rhost : "(none)", score, tier);

    /* Surface the tier decision to the bridge for logging. */
    {
        char info_msg[64];
        snprintf(info_msg, sizeof(info_msg),
                 "INFO:tier=%s score=%d", tier, score);
        info(pamh, info_msg);
    }

    const char *factors[MAX_FACTORS];
    int nfactors = required_factors(score, factors);

    for (int i = 0; i < nfactors; i++) {
        char prompt[64];
        snprintf(prompt, sizeof(prompt), "FACTOR:%s", factors[i]);

        char resp[MAX_RESP_LEN];
        int rc = ask(pamh, PAM_PROMPT_ECHO_OFF, prompt, resp, sizeof(resp));
        if (rc != PAM_SUCCESS) {
            syslog(LOG_AUTH | LOG_ERR,
                   "pam_vpnmfa: conv error on %s (rc=%d)", prompt, rc);
            return PAM_CONV_ERR;
        }

        if (strcmp(resp, "OK") == 0) {
            continue;
        }
        if (strcmp(resp, "UNAVAILABLE") == 0) {
            syslog(LOG_AUTH | LOG_WARNING,
                   "pam_vpnmfa: factor %s unavailable for user=%s",
                   factors[i], user);
            return PAM_AUTHINFO_UNAVAIL;
        }
        /* Anything else (FAIL, empty, etc.) is a hard failure. */
        syslog(LOG_AUTH | LOG_WARNING,
               "pam_vpnmfa: factor %s rejected for user=%s (resp=%s)",
               factors[i], user, resp[0] ? resp : "(empty)");
        return PAM_AUTH_ERR;
    }

    syslog(LOG_AUTH | LOG_INFO,
           "pam_vpnmfa: user=%s authenticated (tier=%s, %d factor(s))",
           user, tier, nfactors);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
