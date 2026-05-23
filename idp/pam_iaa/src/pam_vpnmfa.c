/*
 * pam_vpnmfa.c — PAM module for VPN MFA orchestration
 *
 * This module is loaded by the IdP's PAM profile and:
 *   1. Queries the IdP's /pam/factors endpoint to get required factors
 *      for this user (based on RBA score already computed by IdP)
 *   2. Collects credentials via PAM conversation function
 *   3. Posts results to /pam/verify endpoint
 *   4. Returns PAM_SUCCESS or PAM_AUTH_ERR
 *
 * Build:
 *   gcc -shared -fPIC -o pam_vpnmfa.so pam_vpnmfa.c \
 *       -lpam -lcurl -o /lib/security/pam_vpnmfa.so
 *
 * PAM config (/etc/pam.d/vpnauth):
 *   auth required pam_vpnmfa.so idp_url=http://localhost:8080 \
 *                                session_param=PAM_SESSION_ID
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>

/* We use libcurl for HTTP — link with -lcurl */
#include <curl/curl.h>

#define MAX_URL     512
#define MAX_FACTOR  64
#define MAX_FACTORS 8
#define MAX_RESP    256

/* ── libcurl response buffer ─────────────────────────────────────────────── */

typedef struct {
    char   *data;
    size_t  size;
} ResponseBuf;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    ResponseBuf *buf = (ResponseBuf *)userdata;
    size_t total     = size * nmemb;
    buf->data        = realloc(buf->data, buf->size + total + 1);
    if (!buf->data) return 0;
    memcpy(buf->data + buf->size, ptr, total);
    buf->size        += total;
    buf->data[buf->size] = '\0';
    return total;
}

static ResponseBuf *http_get(const char *url) {
    CURL       *curl = curl_easy_init();
    ResponseBuf *buf = calloc(1, sizeof(ResponseBuf));
    if (!curl || !buf) return NULL;

    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       10L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(buf->data);
        free(buf);
        return NULL;
    }
    return buf;
}

static ResponseBuf *http_post(const char *url, const char *postdata) {
    CURL        *curl = curl_easy_init();
    ResponseBuf *buf  = calloc(1, sizeof(ResponseBuf));
    if (!curl || !buf) return NULL;

    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    postdata);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       10L);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(buf->data);
        free(buf);
        return NULL;
    }
    return buf;
}

/* ── Minimal JSON helpers (no external lib) ──────────────────────────────── */

/*
 * Extract a string value from flat JSON like {"key":"value"}.
 * dst must be at least dst_len bytes. Returns 1 on success.
 */
static int json_get_str(const char *json, const char *key,
                         char *dst, size_t dst_len) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *pos = strstr(json, needle);
    if (!pos) return 0;
    pos += strlen(needle);
    while (*pos == ' ' || *pos == ':') pos++;
    if (*pos != '"') return 0;
    pos++;   /* skip opening quote */
    size_t i = 0;
    while (*pos && *pos != '"' && i < dst_len - 1)
        dst[i++] = *pos++;
    dst[i] = '\0';
    return 1;
}

/*
 * Parse a JSON array of strings ["a","b","c"] into out[].
 * Returns count.
 */
static int json_get_str_array(const char *json, const char *key,
                               char out[][MAX_FACTOR], int max_out) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *pos = strstr(json, needle);
    if (!pos) return 0;
    pos += strlen(needle);
    while (*pos && *pos != '[') pos++;
    if (*pos != '[') return 0;
    pos++;

    int count = 0;
    while (*pos && *pos != ']' && count < max_out) {
        while (*pos == ' ' || *pos == ',') pos++;
        if (*pos != '"') { pos++; continue; }
        pos++;
        size_t i = 0;
        while (*pos && *pos != '"' && i < MAX_FACTOR - 1)
            out[count][i++] = *pos++;
        out[count][i] = '\0';
        if (*pos == '"') pos++;
        count++;
    }
    return count;
}

/* ── PAM conversation helper ─────────────────────────────────────────────── */

static int ask_user(pam_handle_t *pamh, int style,
                     const char *prompt, char *resp, size_t resp_len) {
    const struct pam_conv *conv;
    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS)
        return PAM_CONV_ERR;

    struct pam_message  msg  = { .msg_style = style, .msg = prompt };
    struct pam_message *msgp = &msg;
    struct pam_response *r   = NULL;

    int ret = conv->conv(1, (const struct pam_message **)&msgp, &r, conv->appdata_ptr);
    if (ret != PAM_SUCCESS || !r) return PAM_CONV_ERR;

    if (r->resp) {
        strncpy(resp, r->resp, resp_len - 1);
        resp[resp_len - 1] = '\0';
        free(r->resp);
    }
    free(r);
    return PAM_SUCCESS;
}

/* ── Module entry point ───────────────────────────────────────────────────── */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *username   = NULL;
    char        idp_url[MAX_URL]    = "http://localhost:8080";
    char        session_id[MAX_RESP] = "";

    /* Parse module arguments */
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "idp_url=", 8) == 0)
            strncpy(idp_url, argv[i] + 8, sizeof(idp_url) - 1);
        else if (strncmp(argv[i], "session_id=", 11) == 0)
            strncpy(session_id, argv[i] + 11, sizeof(session_id) - 1);
    }

    /* Get username */
    if (pam_get_user(pamh, &username, "Username: ") != PAM_SUCCESS || !username) {
        syslog(LOG_AUTH|LOG_ERR, "pam_vpnmfa: cannot get username");
        return PAM_AUTH_ERR;
    }

    syslog(LOG_AUTH|LOG_INFO, "pam_vpnmfa: authenticating user=%s", username);

    /* ── 1. Query required factors from IdP ─────────────────────────────── */
    char url[MAX_URL + 256];
    snprintf(url, sizeof(url),
             "%s/pam/factors?username=%s&session_id=%s",
             idp_url, username, session_id);

    ResponseBuf *factors_resp = http_get(url);
    if (!factors_resp) {
        syslog(LOG_AUTH|LOG_ERR, "pam_vpnmfa: cannot reach IdP");
        pam_info(pamh, "Authentication server unreachable.");
        return PAM_AUTHINFO_UNAVAIL;
    }

    char factors[MAX_FACTORS][MAX_FACTOR];
    int  nfactors = json_get_str_array(factors_resp->data, "factors",
                                        factors, MAX_FACTORS);
    free(factors_resp->data);
    free(factors_resp);

    if (nfactors == 0) {
        syslog(LOG_AUTH|LOG_ERR, "pam_vpnmfa: no factors returned for %s", username);
        return PAM_AUTH_ERR;
    }

    syslog(LOG_AUTH|LOG_INFO, "pam_vpnmfa: %d factor(s) required", nfactors);

    /* ── 2. Collect each factor via conversation function ────────────────── */
    char collected_password[MAX_RESP] = "";
    char collected_totp[MAX_RESP]     = "";

    for (int i = 0; i < nfactors; i++) {
        const char *factor = factors[i];

        if (strcmp(factor, "password") == 0) {
            if (ask_user(pamh, PAM_PROMPT_ECHO_OFF,
                          "Password: ",
                          collected_password, sizeof(collected_password))
                    != PAM_SUCCESS) {
                syslog(LOG_AUTH|LOG_ERR, "pam_vpnmfa: conversation failed (password)");
                return PAM_CONV_ERR;
            }

        } else if (strcmp(factor, "totp") == 0) {
            if (ask_user(pamh, PAM_PROMPT_ECHO_ON,
                          "Authenticator code: ",
                          collected_totp, sizeof(collected_totp))
                    != PAM_SUCCESS) {
                syslog(LOG_AUTH|LOG_ERR, "pam_vpnmfa: conversation failed (totp)");
                return PAM_CONV_ERR;
            }

        } else if (strcmp(factor, "fido2") == 0) {
            /* FIDO2 is handled in the browser — PAM just signals it's needed */
            pam_info(pamh, "FIDO2: complete authentication in your browser.");
            /* The IdP MFA session tracks fido2_ok separately via the web flow.
               We trust the IdP session state here. */
        }
    }

    /* ── 3. POST collected credentials to IdP /pam/verify ───────────────── */
    char postdata[1024];
    char *enc_user = curl_easy_escape(NULL, username,             0);
    char *enc_pass = curl_easy_escape(NULL, collected_password,   0);
    char *enc_totp = curl_easy_escape(NULL, collected_totp,       0);
    char *enc_sid  = curl_easy_escape(NULL, session_id,           0);

    snprintf(postdata, sizeof(postdata),
             "username=%s&password=%s&totp=%s&session_id=%s",
             enc_user  ? enc_user : "",
             enc_pass  ? enc_pass : "",
             enc_totp  ? enc_totp : "",
             enc_sid   ? enc_sid  : "");

    curl_free(enc_user); curl_free(enc_pass);
    curl_free(enc_totp); curl_free(enc_sid);

    snprintf(url, sizeof(url), "%s/pam/verify", idp_url);
    ResponseBuf *verify_resp = http_post(url, postdata);

    if (!verify_resp) {
        syslog(LOG_AUTH|LOG_ERR, "pam_vpnmfa: /pam/verify unreachable");
        return PAM_AUTHINFO_UNAVAIL;
    }

    char status[64] = "";
    json_get_str(verify_resp->data, "status", status, sizeof(status));
    free(verify_resp->data);
    free(verify_resp);

    if (strcmp(status, "ok") == 0) {
        syslog(LOG_AUTH|LOG_INFO, "pam_vpnmfa: user=%s authenticated OK", username);
        return PAM_SUCCESS;
    }

    syslog(LOG_AUTH|LOG_WARNING, "pam_vpnmfa: user=%s auth FAILED", username);
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
    return PAM_SUCCESS;
}
