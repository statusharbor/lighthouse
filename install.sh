#!/usr/bin/env sh
# Lighthouse agent installer.
#
# Usage:
#   curl -fsSL https://lighthouse.statusharbor.io/install.sh \
#     | LIGHTHOUSE_TOKEN=<token-from-console> sh
#
# This script:
#   1. Detects OS/arch.
#   2. Downloads the latest signed release binary from GitHub Releases.
#   3. Verifies the SHA256 checksum.
#   4. Writes lighthouse.yaml with the supplied token.
#   5. Installs a systemd unit (Linux) or launchd plist (macOS), or prints
#      run instructions on unsupported init systems.
#
# All steps are POSIX sh — no bashisms — so it runs on minimal Alpine /
# busybox images that ops shops often use for monitoring boxes.

set -eu

REPO="statusharbor/lighthouse"
INSTALL_DIR="${LIGHTHOUSE_INSTALL_DIR:-/usr/local/bin}"
DATA_DIR="${LIGHTHOUSE_DATA_DIR:-/var/lib/lighthouse}"
CONFIG_PATH="${LIGHTHOUSE_CONFIG:-/etc/lighthouse/lighthouse.yaml}"

die() { printf '\nlighthouse install: %s\n' "$1" >&2; exit 1; }
note() { printf '==> %s\n' "$1"; }

# Detect upgrade mode. An existing config + binary tells us this is a
# re-run on a host that already has the agent (the Console's
# UpgradeModal hands operators the same one-liner as the first-install
# instructions, deliberately - one URL to remember). Skip the token
# requirement (token already lives in $CONFIG_PATH), skip the config
# write (don't clobber operator-edited settings), and skip the unit /
# plist write (respect any /etc/systemd/system/lighthouse.service.d/
# drop-ins). Binary refresh + checksum still run, and the service
# restarts so systemd / launchd picks up the new ExecStart inode.
upgrade_mode=false
if [ -f "$CONFIG_PATH" ] && [ -x "${INSTALL_DIR}/lighthouse" ]; then
    upgrade_mode=true
fi

if [ "$upgrade_mode" = "false" ]; then
    [ -n "${LIGHTHOUSE_TOKEN:-}" ] || die "LIGHTHOUSE_TOKEN environment variable is required (mint one from your Status Harbor Console)"
else
    note "upgrade detected - keeping existing config at ${CONFIG_PATH}"
fi

# --- detect platform -------------------------------------------------------
uname_s=$(uname -s 2>/dev/null || echo unknown)
uname_m=$(uname -m 2>/dev/null || echo unknown)

case "$uname_s" in
    Linux)  os="linux" ;;
    Darwin) os="darwin" ;;
    *)      die "unsupported OS: $uname_s" ;;
esac

case "$uname_m" in
    x86_64|amd64)  arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)             die "unsupported architecture: $uname_m" ;;
esac

note "platform: ${os}_${arch}"

# --- pick a downloader -----------------------------------------------------
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q "$1" -O "$2"; }
else
    die "neither curl nor wget found"
fi

# --- discover latest release ----------------------------------------------
# Use github.com's /releases/latest redirect rather than api.github.com.
# The API path is rate-limited to 60 req/hr per IP for unauthenticated
# callers, which trips on any sufficiently busy office or NAT'd network
# (we hit it ourselves). The redirect lives on github.com and doesn't
# share that budget.
note "discovering latest release"
latest_url="https://github.com/${REPO}/releases/latest"
if command -v curl >/dev/null 2>&1; then
    tag=$(curl -fsSI -o /dev/null -w '%{redirect_url}' "$latest_url" \
        | sed -n 's|.*/tag/\(.*\)$|\1|p' | tr -d '\r\n')
else
    # wget: -S writes response headers to stderr; --max-redirect=0 keeps
    # wget from following so the Location header is what we read.
    tag=$(wget -qS --max-redirect=0 -O /dev/null "$latest_url" 2>&1 \
        | sed -n 's|.*[Ll]ocation: .*/tag/\(.*\)$|\1|p' | tr -d '\r\n')
fi
[ -n "$tag" ] || die "could not discover latest release tag from github.com redirect"
note "version: $tag"

binary_name="lighthouse_${os}_${arch}"
binary_url="https://github.com/${REPO}/releases/download/${tag}/${binary_name}"
checksum_url="https://github.com/${REPO}/releases/download/${tag}/checksums.txt"

# --- download + verify -----------------------------------------------------
tmp_bin=$(mktemp)
tmp_sums=$(mktemp)
trap 'rm -f "$tmp_bin" "$tmp_sums"' EXIT

note "downloading $binary_name"
fetch "$binary_url" "$tmp_bin"
fetch "$checksum_url" "$tmp_sums"

if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp_bin" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$tmp_bin" | awk '{print $1}')
else
    die "no sha256 utility found (sha256sum or shasum required)"
fi

expected=$(grep " ${binary_name}\$" "$tmp_sums" | awk '{print $1}' || true)
[ -n "$expected" ] || die "${binary_name} not in checksums.txt"
[ "$actual" = "$expected" ] || die "checksum mismatch (expected $expected, got $actual)"
note "checksum verified"

# --- install ---------------------------------------------------------------
sudo_cmd=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        sudo_cmd="sudo"
    else
        die "must run as root or have sudo (writing to ${INSTALL_DIR})"
    fi
fi

note "installing to ${INSTALL_DIR}/lighthouse"
$sudo_cmd install -m 0755 "$tmp_bin" "${INSTALL_DIR}/lighthouse"

# Write config + ensure data dir. Skipped on upgrade so an operator who
# tweaked log_level / data_dir / extra fields doesn't lose them on a
# re-run; the existing token in $CONFIG_PATH stays the source of truth.
if [ "$upgrade_mode" = "false" ]; then
    $sudo_cmd mkdir -p "$(dirname "$CONFIG_PATH")" "$DATA_DIR"
    note "writing config to ${CONFIG_PATH}"
    # shellcheck disable=SC2024
    $sudo_cmd sh -c "cat > '${CONFIG_PATH}'" <<EOF
# Lighthouse agent configuration. Generated by install.sh.
token: ${LIGHTHOUSE_TOKEN}

agent:
  data_dir: ${DATA_DIR}
  log_level: info
EOF
    $sudo_cmd chmod 0600 "$CONFIG_PATH"
fi

# --- service unit ----------------------------------------------------------
# On upgrade we leave the unit / plist file alone (operator may have a
# drop-in or a manual edit we shouldn't clobber) and just restart the
# service so the new binary's ExecStart picks up.
case "$os" in
    linux)
        if [ -d /run/systemd/system ]; then
            if [ "$upgrade_mode" = "true" ]; then
                note "restarting systemd service to pick up the new binary"
                $sudo_cmd systemctl restart lighthouse.service
            else
                note "installing systemd unit"
                $sudo_cmd sh -c "cat > /etc/systemd/system/lighthouse.service" <<EOF
[Unit]
Description=Status Harbor Lighthouse Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/lighthouse -config ${CONFIG_PATH}
# Restart on crash, NOT on clean exit. The agent exits with 0 when the
# Console says the lighthouse has been deleted (401/410); restart=always
# would keep relaunching it into an immediate exit forever.
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
                $sudo_cmd systemctl daemon-reload
                $sudo_cmd systemctl enable --now lighthouse.service
                note "systemd service started: systemctl status lighthouse"
            fi
        else
            note "systemd not detected - start manually as root: sudo ${INSTALL_DIR}/lighthouse -config ${CONFIG_PATH}"
            note "(the config at ${CONFIG_PATH} is mode 0600 root:root because it carries the agent token)"
        fi
        ;;
    darwin)
        plist_path="/Library/LaunchDaemons/io.statusharbor.lighthouse.plist"
        log_dir="/var/log/lighthouse"
        if [ "$upgrade_mode" = "true" ]; then
            note "kicking launchd daemon to pick up the new binary"
            # kickstart -k stops the running instance (if any) and
            # respawns it via the existing plist; no need to bootout +
            # bootstrap on upgrade.
            $sudo_cmd launchctl kickstart -k system/io.statusharbor.lighthouse
        else
        $sudo_cmd mkdir -p "$log_dir"
        note "installing launchd daemon at $plist_path"
        # shellcheck disable=SC2024
        $sudo_cmd sh -c "cat > '$plist_path'" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.statusharbor.lighthouse</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/lighthouse</string>
        <string>-config</string>
        <string>${CONFIG_PATH}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <!-- Keep alive on crash but NOT on clean exit. The agent exits with 0
         when the Console says the lighthouse has been deleted; an
         unconditional KeepAlive=true would relaunch it into an immediate
         exit forever. -->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>StandardOutPath</key>
    <string>${log_dir}/lighthouse.log</string>
    <key>StandardErrorPath</key>
    <string>${log_dir}/lighthouse.err.log</string>
    <key>WorkingDirectory</key>
    <string>${DATA_DIR}</string>
</dict>
</plist>
EOF
        $sudo_cmd chmod 0644 "$plist_path"
        $sudo_cmd chown root:wheel "$plist_path"
        # bootout first in case a previous version is loaded; ignore the
        # error when nothing is currently registered.
        $sudo_cmd launchctl bootout system "$plist_path" 2>/dev/null || true
        $sudo_cmd launchctl bootstrap system "$plist_path"
        note "launchd daemon started: sudo launchctl print system/io.statusharbor.lighthouse"
        note "logs: $log_dir/lighthouse.log"
        fi
        ;;
esac

if [ "$upgrade_mode" = "true" ]; then
    note "lighthouse upgraded. The Console will show the new agent_version on the next heartbeat."
else
    note "lighthouse installed. Visit your Status Harbor Console to verify the agent is online."
fi
