FROM python:3.12-slim
WORKDIR /app

# Build-time: gcc + libpam-dev for the C PAM orchestrator module (§2.4/§2.9).
# Runtime:   libpam0g comes in as a libpam-dev dep, so the .so loads at boot.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libpam-dev \
    && rm -rf /var/lib/apt/lists/*

COPY idp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY idp/    ./idp/
COPY common/ ./common/

# Build and install the IAA-VPN PAM orchestrator.
# pam_permit.so is the canonical reference for "where PAM modules live"; we
# install ours next to it so libpam0g picks it up without extra search paths.
RUN PAM_DIR="$(dirname "$(dpkg -L libpam-modules | grep -m1 pam_permit.so)")" \
    && echo "Installing pam_vpnmfa.so to $PAM_DIR" \
    && make -C idp/pam_iaa TARGET="$PAM_DIR/pam_vpnmfa.so"

# Install the PAM service profile for service name "iaa-vpn".
RUN install -D -m 644 idp/pam_iaa/pam.d/iaa-vpn /etc/pam.d/iaa-vpn

RUN mkdir -p /data
ENV PYTHONPATH=/app

CMD ["python", "-m", "idp.app"]
