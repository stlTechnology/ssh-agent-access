#!/usr/bin/env bash
# setup-ssh-agent-access.sh
#
# Sets up key-only SSH access to a Debian or Ubuntu machine for an automated agent.
#   1. Generates a named keypair (ed25519, or RSA-4096 for OpenSSH < 6.5 servers).
#   2. Connects with an existing admin account (one password prompt) and installs the public key.
#   3. Optionally creates the target user and gives it passwordless sudo (sudoers checked with visudo first).
#   4. Logs in as the target user with the key only, to confirm it works.
#
# The admin's sudo password is sent to the remote host on ssh stdin. It is never
# on a command line, never written to a file, and never echoed.
#
# Requirements (on the machine you run this from): bash, ssh, ssh-keygen, base64 (GNU coreutils).
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

for exe in ssh ssh-keygen base64; do
    command -v "$exe" >/dev/null 2>&1 || die "$exe not found on this machine."
done

SSH_DIR="$HOME/.ssh"
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

echo ""
echo "=== SSH agent access setup ==="
echo "Target: Debian / Ubuntu machines (modern or legacy)"
echo ""

read -rp "Purpose label for this keypair (e.g. dev-agent, backup-agent): " PURPOSE
read -rp "Target machine IP or hostname: " TARGET_HOST
read -rp "SSH port [22]: " TARGET_PORT
TARGET_PORT=${TARGET_PORT:-22}
read -rp "Existing admin username to connect with: " ADMIN_USER
read -rp "Remote username to grant key access to (created if missing): " TARGET_USER

[[ -n "$PURPOSE" && -n "$TARGET_HOST" && -n "$ADMIN_USER" && -n "$TARGET_USER" ]] || die "Purpose, host, admin user and target user are required."
[[ "$TARGET_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "Target user name '$TARGET_USER' is not a valid Linux user name."
[[ "$TARGET_PORT" =~ ^[0-9]+$ ]] || die "Port must be a number."

CREATE_USER=no
read -rp "Create '$TARGET_USER' on the remote machine if it does not exist? (y/n) [y]: " yn
[[ "${yn:-y}" =~ ^[Yy] ]] && CREATE_USER=yes

ADD_SUDO=no
read -rp "Add '$TARGET_USER' to passwordless sudoers? (y/n) [n]: " yn
[[ "${yn:-n}" =~ ^[Yy] ]] && ADD_SUDO=yes

# ── Probe the server version to choose a key type ─────────────────────────────
echo ""
echo "Probing $TARGET_HOST for SSH version..."
probe=$(ssh -v -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 \
            -p "$TARGET_PORT" "probe@$TARGET_HOST" exit 2>&1 || true)

if grep -q "REMOTE HOST IDENTIFICATION HAS CHANGED" <<<"$probe"; then
    echo ""
    echo "HOST KEY MISMATCH: the key saved for $TARGET_HOST no longer matches the machine at that address."
    echo "A rebuilt machine on a reused IP is the usual cause. A man-in-the-middle is the other."
    echo "If you know the machine was rebuilt, remove the old entry and run this again:"
    echo "    ssh-keygen -R $TARGET_HOST"
    [[ "$TARGET_PORT" != 22 ]] && echo "    ssh-keygen -R [$TARGET_HOST]:$TARGET_PORT"
    exit 1
fi

KEY_TYPE=ed25519
LEGACY_OPTS=()
ver=$(grep -oE 'remote software version OpenSSH_[0-9]+\.[0-9]+' <<<"$probe" | head -1 || true)
if [[ -z "$ver" ]]; then
    echo "  Could not determine remote version - assuming modern (ed25519)."
else
    echo "  ${ver#remote software version }"
    major=$(sed -E 's/.*OpenSSH_([0-9]+)\..*/\1/' <<<"$ver")
    minor=$(sed -E 's/.*OpenSSH_[0-9]+\.([0-9]+).*/\1/' <<<"$ver")
    if (( major < 6 || (major == 6 && minor < 5) )); then
        KEY_TYPE=rsa
        LEGACY_OPTS=(-o "PubkeyAcceptedKeyTypes=+ssh-rsa" -o "HostKeyAlgorithms=+ssh-rsa")
        echo "  Legacy server (<6.5): ed25519 unsupported - using RSA-4096 with legacy algorithms."
    fi
fi

# ── Keypair ───────────────────────────────────────────────────────────────────
SAFE_PURPOSE=${PURPOSE//[^a-zA-Z0-9_-]/_}
SAFE_HOST=${TARGET_HOST//[^a-zA-Z0-9_-]/_}
KEY_PATH="$SSH_DIR/${SAFE_PURPOSE}_${SAFE_HOST}_${KEY_TYPE}"

echo ""
if [[ -f "$KEY_PATH" ]]; then
    echo "Using existing keypair: $KEY_PATH"
else
    echo "Generating keypair: $KEY_PATH"
    kg_args=(-t "$KEY_TYPE" -f "$KEY_PATH" -N "" -C "${PURPOSE}@agent")
    [[ "$KEY_TYPE" == rsa ]] && kg_args+=(-b 4096)
    ssh-keygen "${kg_args[@]}" >/dev/null
fi
PUB_B64=$(base64 -w0 < "$KEY_PATH.pub")

HK_OPTS=(-o StrictHostKeyChecking=accept-new -p "$TARGET_PORT" "${LEGACY_OPTS[@]}")

# ── Phase 1: install the key for the ADMIN account (SSH prompts for its password) ──
echo ""
echo "Phase 1: installing key for $ADMIN_USER@$TARGET_HOST"
echo "  You will be prompted for ${ADMIN_USER}'s SSH password."

bootstrap="umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; \
printf '\n' >> ~/.ssh/authorized_keys; echo $PUB_B64 | base64 -d >> ~/.ssh/authorized_keys; \
printf '\n' >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; echo BOOTSTRAP_OK"

if ! out=$(ssh "${HK_OPTS[@]}" "$ADMIN_USER@$TARGET_HOST" "$bootstrap" 2>&1) || ! grep -q BOOTSTRAP_OK <<<"$out"; then
    echo "$out" >&2
    die "Phase 1 failed - could not install the key for $ADMIN_USER."
fi
echo "  Key installed for $ADMIN_USER."

# ── Sudo password, only if the admin account is not already root ───────────────
ID_OPTS=("${HK_OPTS[@]}" -i "$KEY_PATH" -o BatchMode=yes)
uid=$(ssh "${ID_OPTS[@]}" "$ADMIN_USER@$TARGET_HOST" 'id -u' 2>/dev/null || echo "?")

SUDO_PASS=""
if [[ "$uid" != 0 && ( "$CREATE_USER" == yes || "$ADD_SUDO" == yes || "$TARGET_USER" != "$ADMIN_USER" ) ]]; then
    echo ""
    read -rsp "Sudo password for $ADMIN_USER on $TARGET_HOST: " SUDO_PASS
    echo ""
fi

# ── Phase 2: provision over key auth ──────────────────────────────────────────
# Build the remote script with its values quoted, then send it base64-encoded as
# an argument. The sudo password goes on stdin, as the first line.
payload=$(mktemp)
trap 'rm -f "$payload"' EXIT
{
    printf 'TU=%q\nPUB_B64=%q\nCREATE_USER=%q\nADD_SUDO=%q\n' \
        "$TARGET_USER" "$PUB_B64" "$CREATE_USER" "$ADD_SUDO"
    cat <<'REMOTE'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin:$PATH

if [ "$(id -u)" -eq 0 ]; then
    s() { "$@"; }
else
    # Password goes to sudo's stdin. Never pipe data into s(): stdin belongs to sudo.
    s() { printf '%s\n' "$SUDOPASS" | sudo -S -p '' "$@"; }
fi

if [ "$CREATE_USER" = yes ]; then
    if id "$TU" >/dev/null 2>&1; then
        echo "  User $TU already exists"
    else
        s useradd -m -s /bin/bash "$TU"
        echo "  Created user $TU"
    fi
fi

if [ "$ADD_SUDO" = yes ]; then
    command -v sudo >/dev/null 2>&1 || { echo "ERROR: sudo is not installed on this host" >&2; exit 3; }
    T=$(mktemp)
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$TU" > "$T"
    # Check before installing: a bad sudoers file locks everyone out.
    s visudo -c -f "$T" >/dev/null
    s install -m 440 -o root -g root "$T" "/etc/sudoers.d/$TU"
    rm -f "$T"
    echo "  Passwordless sudo installed for $TU"
fi

HOMEDIR=$(getent passwd "$TU" | cut -d: -f6)
[ -n "$HOMEDIR" ] || HOMEDIR="/home/$TU"
AK="$HOMEDIR/.ssh/authorized_keys"
KEYLINE=$(printf '%s' "$PUB_B64" | base64 -d)

s mkdir -p "$HOMEDIR/.ssh"
s touch "$AK"
if ! s grep -qxF "$KEYLINE" "$AK"; then
    KT=$(mktemp)
    printf '%s\n' "$KEYLINE" > "$KT"
    s sh -c "cat '$KT' >> '$AK'"
    rm -f "$KT"
fi
s chmod 700 "$HOMEDIR/.ssh"
s chmod 600 "$AK"
s chown -R "$TU:$TU" "$HOMEDIR/.ssh"
echo KEY_INSTALLED
REMOTE
} > "$payload"

SCRIPT_B64=$(base64 -w0 < "$payload")

echo ""
echo "Phase 2: provisioning '$TARGET_USER'..."
# The remote command reads the password line from stdin into SUDOPASS, then runs the script.
remote_cmd="IFS= read -r SUDOPASS; export SUDOPASS; echo '$SCRIPT_B64' | base64 -d | bash"
if ! out=$(printf '%s\n' "$SUDO_PASS" | ssh "${ID_OPTS[@]}" "$ADMIN_USER@$TARGET_HOST" "$remote_cmd" 2>&1) \
   || ! grep -q KEY_INSTALLED <<<"$out"; then
    echo "$out" >&2
    die "Phase 2 failed. See output above."
fi
sed 's/^/  /' <<<"$out" | grep -v KEY_INSTALLED || true

# ── Verify: log in AS the target user with the key only ───────────────────────
echo ""
echo "Verifying key-only login as $TARGET_USER..."
check='whoami'
[[ "$ADD_SUDO" == yes ]] && check='whoami && sudo -n whoami'
vout=$(ssh -i "$KEY_PATH" -o BatchMode=yes "${HK_OPTS[@]}" "$TARGET_USER@$TARGET_HOST" "$check" 2>&1 || true)

if grep -qx "$TARGET_USER" <<<"$vout"; then
    echo "  Login OK as $TARGET_USER"
    if [[ "$ADD_SUDO" == yes ]]; then
        if grep -qx root <<<"$vout"; then
            echo "  Passwordless sudo OK"
        else
            echo "  WARNING: passwordless sudo did NOT verify."
        fi
    fi
else
    echo "  WARNING: verification failed: $vout"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
legacy_text=""
if (( ${#LEGACY_OPTS[@]} )); then
    legacy_text=" -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa"
fi
cat <<EOF

======================================================================
 Setup complete
======================================================================

  Purpose     : $PURPOSE
  Host        : $TARGET_HOST
  User        : $TARGET_USER
  Key type    : $KEY_TYPE
  Private key : $KEY_PATH

  Connect with:
    ssh -i "$KEY_PATH"$legacy_text -p $TARGET_PORT $TARGET_USER@$TARGET_HOST

  Or add to ~/.ssh/config:
    Host $SAFE_PURPOSE
        HostName     $TARGET_HOST
        User         $TARGET_USER
        IdentityFile $KEY_PATH
        Port         $TARGET_PORT

  Then: ssh $SAFE_PURPOSE
======================================================================
EOF
