# setup-ssh-agent-access.ps1
# Generates a named SSH keypair, connects to a Debian/Ubuntu machine using an
# existing admin account, optionally creates the target user + passwordless
# sudo, installs the public key, and verifies key-only login works.
#
# Usage: powershell.exe -ExecutionPolicy Bypass -File setup-ssh-agent-access.ps1
#
# Requirements: Windows OpenSSH client (ssh.exe / ssh-keygen.exe) - built into
# Windows 10/11. NO PowerShell modules, NO internet access needed.
#
# 2026-08-09 rewrite: dropped Posh-SSH. Its SSH.NET transport cannot negotiate
# modern key exchange (Ubuntu 24.04 offers sntrup761x25519-sha512@openssh.com)
# and failed with "Key exchange negotiation failed". Native ssh.exe handles
# both modern and legacy hosts. Also added auto-detection of pre-6.5 servers,
# which cannot use ed25519 keys at all (e.g. Debian 7 / TurnKey appliances).

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Preflight ──────────────────────────────────────────────────────────────────
foreach ($exe in 'ssh', 'ssh-keygen') {
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
        throw "$exe not found. Install the Windows OpenSSH Client feature."
    }
}

# ── Helpers ────────────────────────────────────────────────────────────────────

# ssh writes plenty of harmless chatter to stderr. Under PowerShell 7 with
# $ErrorActionPreference='Stop', merging that with 2>&1 can throw before we ever
# get to inspect the exit code - so every native call goes through here, which
# relaxes the preference just for the duration and hands back a plain result.
function Invoke-Ssh {
    param([string[]]$SshArgs, [AllowNull()][string]$StdIn = $null)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($null -ne $StdIn) {
            $out = $StdIn | & ssh @SshArgs 2>&1
        } else {
            $out = & ssh @SshArgs 2>&1
        }
        return [pscustomobject]@{
            Output   = @($out | ForEach-Object { $_.ToString() })
            Text     = (@($out | ForEach-Object { $_.ToString() }) -join ' ')
            ExitCode = $LASTEXITCODE
        }
    } finally { $ErrorActionPreference = $prev }
}

function Ask {
    param([string]$Prompt, [string]$Default = '')
    $hint = if ($Default -ne '') { " [$Default]" } else { '' }
    $val  = Read-Host "$Prompt$hint"
    if ($val -eq '' -and $Default -ne '') { return $Default }
    return $val
}

# ssh-keygen is just as chatty on stderr as ssh - same relaxation applies.
function Invoke-SshKeygen {
    param([string[]]$KeygenArgs)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & ssh-keygen @KeygenArgs 2>&1
        return [pscustomobject]@{
            Text     = (@($out | ForEach-Object { $_.ToString() }) -join ' ')
            ExitCode = $LASTEXITCODE
        }
    } finally { $ErrorActionPreference = $prev }
}

# Ask the server what it is, so we can pick a key type it can actually parse.
# ed25519 needs OpenSSH >= 6.5; older hosts also need legacy algorithm opt-ins.
# The version banner is exchanged BEFORE host key verification, so this probe
# still reports a version when the saved host key no longer matches - the
# caller inspects the same output for that conflict separately.
function Invoke-SshProbe {
    param([string]$TargetHost, [string]$Port)
    return Invoke-Ssh @('-v', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new',
                        '-o', 'ConnectTimeout=8', '-p', $Port, "probe@$TargetHost", 'exit')
}

function Get-RemoteSshVersion {
    param([pscustomobject]$Res)
    $line = $Res.Output | Select-String -Pattern 'remote software version OpenSSH_([0-9]+)\.([0-9]+)'
    if ($line) {
        $m = $line.Matches[0]
        return [pscustomobject]@{
            Major = [int]$m.Groups[1].Value
            Minor = [int]$m.Groups[2].Value
            Raw   = $m.Value
        }
    }
    return $null
}

function New-SSHKeyPair {
    param([string]$KeyPath, [string]$Comment, [string]$Type)
    # NB: do not name this $args - that is an automatic variable in PowerShell.
    $kgArgs = @('-t', $Type, '-f', $KeyPath, '-N', '', '-C', $Comment)
    if ($Type -eq 'rsa') { $kgArgs += @('-b', '4096') }
    & ssh-keygen @kgArgs | Out-Host
    if (-not (Test-Path ($KeyPath + '.pub'))) {
        throw 'ssh-keygen failed - public key was not created.'
    }
}

# ── Gather info ────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '=== SSH Agent Access Setup ===' -ForegroundColor Cyan
Write-Host 'Target: Debian / Ubuntu machines (modern or legacy)'
Write-Host ''

$Purpose    = Ask 'Purpose label for this keypair (e.g. dev-agent, backup-agent)'
$TargetHost = Ask 'Target machine IP or hostname'
$TargetPort = Ask 'SSH port' '22'
$AdminUser  = Ask 'Existing admin username to connect with'
$TargetUser = Ask 'Remote username to grant key access to (created if missing)'

$CreateUser = $false
$AddSudo    = $false

Write-Host ''
$yn = Ask "Create '$TargetUser' on the remote machine if it does not exist? (y/n)" 'y'
if ($yn -match '^[Yy]') {
    $CreateUser = $true
    $yn2 = Ask "Add '$TargetUser' to passwordless sudoers? (y/n)" 'n'
    if ($yn2 -match '^[Yy]') { $AddSudo = $true }
}

# ── Probe the server, choose key type ──────────────────────────────────────────
Write-Host ''
Write-Host "Probing $TargetHost for SSH version..." -ForegroundColor Cyan
$probe    = Invoke-SshProbe -TargetHost $TargetHost -Port $TargetPort
$remote   = Get-RemoteSshVersion -Res $probe

# -- Stale host key (reused IP / reimaged machine) -----------------------------
# A recycled address whose old host key is still in known_hosts aborts every
# later ssh call with "REMOTE HOST IDENTIFICATION HAS CHANGED". Surface it here,
# once, and let the operator decide - rather than dying in Phase 1.
$HostKeyOpts    = @('-o', 'StrictHostKeyChecking=accept-new')
$TempKnownHosts = ''
$StaleFixCmds   = @()

# Dot-sourced so it can set the variables above in this scope. Points ssh at a
# throwaway known_hosts: nothing is verified, and nothing is written to the real
# file either.
$UseThrowawayKnownHosts = {
    $TempKnownHosts = Join-Path ([IO.Path]::GetTempPath()) ('known_hosts_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType File -Path $TempKnownHosts -Force | Out-Null
    $HostKeyOpts  = @('-o', 'StrictHostKeyChecking=no', '-o', "UserKnownHostsFile=$TempKnownHosts")
    $StaleFixCmds = @($TargetHost)
    if ($TargetPort -ne '22') { $StaleFixCmds += "[$TargetHost]:$TargetPort" }
    Write-Host '  Host key checking disabled for this run only.' -ForegroundColor Yellow
}

if ($probe.Text -match 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed') {

    # ssh names both the offending file and the new key in its own complaint.
    $khFile = Join-Path $env:USERPROFILE '.ssh\known_hosts'
    $khLine = ''
    if ($probe.Text -match 'Offending [^ ]+ key in (.+?):([0-9]+)') {
        $khFile = $Matches[1] -replace '\\+', '\'
        $khLine = $Matches[2]
    }
    $fp = 'unknown'
    if ($probe.Text -match '(SHA256:[A-Za-z0-9+/=]+)') { $fp = $Matches[1] }

    $where = if ($khLine -ne '') { "$khFile (line $khLine)" } else { $khFile }

    Write-Host ''
    Write-Host '  HOST KEY MISMATCH' -ForegroundColor Red
    Write-Host "  The key saved for $TargetHost does not match the key it is offering now."
    Write-Host "  Saved in    : $where"
    Write-Host "  Offered now : $fp"
    Write-Host '  A reimaged or rebuilt machine on a reused IP address is the ordinary cause;'
    Write-Host '  a man-in-the-middle is the other. Accepting trusts whatever answers at that'
    Write-Host '  address now, so only do it if you know the machine was rebuilt.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '    [r] Remove the stale entry and accept the new key (leaves a working setup)'
    Write-Host '    [i] Ignore host keys for this run only (stale entry stays; later ssh fails)'
    Write-Host '    [a] Abort'
    $hkChoice = Ask '  Choice (r/i/a)' 'r'

    switch -Regex ($hkChoice) {
        '^[Rr]' {
            # -R drops every key type recorded for the name, which is what we
            # want: the stale entry is often a different type than the new key.
            # Both the bare name and the [host]:port form can be present.
            $names = @($TargetHost)
            if ($TargetPort -ne '22') { $names += "[$TargetHost]:$TargetPort" }
            foreach ($n in $names) {
                $rm = Invoke-SshKeygen @('-R', $n, '-f', $khFile)
                if ($rm.ExitCode -ne 0) {
                    Write-Host "  WARNING: ssh-keygen -R $n exited $($rm.ExitCode): $($rm.Text)" -ForegroundColor Yellow
                }
            }
            # -R exits 0 whether or not it matched anything, so prove it worked
            # by probing again instead of trusting the exit code.
            $probe  = Invoke-SshProbe -TargetHost $TargetHost -Port $TargetPort
            $remote = Get-RemoteSshVersion -Res $probe

            if ($probe.Text -match 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed') {
                Write-Host '  The mismatch is STILL there after removal.' -ForegroundColor Red
                Write-Host '  The offending entry is probably in a different file - a global'
                Write-Host '  known_hosts, or one named by UserKnownHostsFile in ~/.ssh/config.'
                $fb = Ask '  Ignore host keys for this run instead? (y/n)' 'n'
                if ($fb -match '^[Yy]') {
                    . $UseThrowawayKnownHosts
                } else {
                    throw "Host key mismatch for $TargetHost persists after ssh-keygen -R. Find the entry with: ssh -v -p $TargetPort probe@$TargetHost"
                }
            } else {
                Write-Host "  Stale entry removed (ssh-keygen left a backup at $khFile.old)." -ForegroundColor Green
            }
        }
        '^[Ii]' {
            . $UseThrowawayKnownHosts
        }
        default {
            throw "Aborted at host key mismatch for $TargetHost. Clear it with: ssh-keygen -R $TargetHost"
        }
    }
}

$KeyType  = 'ed25519'
$LegacyOpts = @()

if ($null -eq $remote) {
    Write-Host '  Could not determine remote version - assuming modern (ed25519).' -ForegroundColor Yellow
} else {
    Write-Host "  $($remote.Raw)"
    if ($remote.Major -lt 6 -or ($remote.Major -eq 6 -and $remote.Minor -lt 5)) {
        $KeyType    = 'rsa'
        # Pre-7.0 servers do not know PubkeyAcceptedKeyTypes themselves, but OUR
        # client needs these to offer an RSA key / accept an RSA host key to them.
        $LegacyOpts = @('-o', 'PubkeyAcceptedKeyTypes=+ssh-rsa',
                        '-o', 'HostKeyAlgorithms=+ssh-rsa')
        Write-Host '  Legacy server (<6.5): ed25519 unsupported - using RSA-4096 + legacy algorithms.' -ForegroundColor Yellow
    }
}

# ── Keypair paths ──────────────────────────────────────────────────────────────
$SafePurpose = $Purpose    -replace '[^a-zA-Z0-9_-]', '_'
$SafeHost    = $TargetHost -replace '[^a-zA-Z0-9_-]', '_'
$KeyName     = "${SafePurpose}_${SafeHost}_$KeyType"
$KeyDir      = Join-Path $env:USERPROFILE '.ssh'
$KeyPath     = Join-Path $KeyDir $KeyName
$PubKeyPath  = $KeyPath + '.pub'

if (-not (Test-Path $KeyDir)) { New-Item -ItemType Directory -Path $KeyDir | Out-Null }

Write-Host ''
if (Test-Path $KeyPath) {
    $yn3 = Ask "Keypair '$KeyName' already exists. Overwrite? (y/n)" 'n'
    if ($yn3 -match '^[Yy]') {
        Remove-Item $KeyPath, $PubKeyPath -ErrorAction SilentlyContinue
        Write-Host "Generating keypair: $KeyName" -ForegroundColor Cyan
        New-SSHKeyPair $KeyPath "${Purpose}@agent" $KeyType
    } else {
        Write-Host 'Using existing keypair.' -ForegroundColor Green
    }
} else {
    Write-Host "Generating keypair: $KeyName" -ForegroundColor Cyan
    New-SSHKeyPair $KeyPath "${Purpose}@agent" $KeyType
}

$PubKey    = (Get-Content $PubKeyPath -Raw).Trim()
$PubKeyB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PubKey))

$CommonOpts = $HostKeyOpts + @('-p', $TargetPort) + $LegacyOpts

# ── Phase 1: install our key for the ADMIN account (one password prompt) ───────
# Everything after this uses key auth, so the admin password is typed exactly
# once and never has to be stored, piped, or embedded anywhere.
Write-Host ''
Write-Host "Phase 1: installing key for $AdminUser@$TargetHost" -ForegroundColor Cyan
Write-Host "  You will be prompted for ${AdminUser}'s SSH password." -ForegroundColor Yellow

# Repairs damage from an older version of this script, which appended keys
# without a guaranteed trailing newline - letting successive runs fuse two
# keys onto one line (an authorized_keys line with more than one key on it
# is invalid, so the fusion silently disabled BOTH keys). Splitting any
# "ssh-<type> " token onto its own line, then dropping blank lines, is a
# no-op on an already-healthy file.
$sanitizeAuthKeys = "sed -i 's/ssh-ed25519/\n&/g; s/ssh-rsa/\n&/g' ~/.ssh/authorized_keys 2>/dev/null; " +
                    "sed -i '/^`$/d' ~/.ssh/authorized_keys 2>/dev/null; "

$bootstrap = "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; " + $sanitizeAuthKeys +
             "{ printf '\n'; echo $PubKeyB64 | base64 -d; printf '\n'; } >> ~/.ssh/authorized_keys; " +
             "chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; echo BOOTSTRAP_OK"

$r1 = Invoke-Ssh ($CommonOpts + @("$AdminUser@$TargetHost", $bootstrap))
$r1.Output | Out-Host
if ($r1.Text -notmatch 'BOOTSTRAP_OK') {
    throw 'Phase 1 failed - could not install key for the admin account.'
}

# ── Sudo password (only if we actually need to escalate) ───────────────────────
$SudoPass = ''
$idRes  = Invoke-Ssh ($CommonOpts + @('-i', $KeyPath, '-o', 'BatchMode=yes', "$AdminUser@$TargetHost", 'id -u'))
$IsRoot = ($idRes.Text.Trim() -eq '0')

if (-not $IsRoot -and ($CreateUser -or $AddSudo -or $TargetUser -ne $AdminUser)) {
    Write-Host ''
    $sec = Read-Host "Enter sudo password for $AdminUser on $TargetHost" -AsSecureString
    $SudoPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}

# ── Phase 2: provision, over key auth ─────────────────────────────────────────
# The remote script is passed as a base64 ARGUMENT (contains no secrets), while
# the sudo password arrives on STDIN - so it never appears in the process list,
# in a temp file, or in the shell history on either end.
$remoteScript = @'
set -euo pipefail
IFS= read -r SUDOPASS || true
SUDOPASS=${SUDOPASS%$'\r'}
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin:$PATH

TU='{{TARGET_USER}}'
PUBKEY_B64='{{PUBKEY_B64}}'
CREATE_USER='{{CREATE_USER}}'
ADD_SUDO='{{ADD_SUDO}}'

if [ "$(id -u)" -eq 0 ]; then
    s() { "$@"; }
else
    # Password goes to sudo's stdin. printf is a bash builtin, so it never
    # shows up in ps. Never pipe data into s() - stdin is reserved for sudo.
    s() { printf '%s\n' "$SUDOPASS" | sudo -S -p '' "$@"; }
fi

if [ "$CREATE_USER" = "yes" ]; then
    if id "$TU" >/dev/null 2>&1; then
        echo "USER_EXISTS"
    else
        s useradd -m -s /bin/bash "$TU"
        echo "USER_CREATED"
    fi
fi

if [ "$ADD_SUDO" = "yes" ]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: sudo is not installed on this host" >&2
        exit 3
    fi
    T=$(mktemp)
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$TU" > "$T"
    # Validate before installing - a bad sudoers file locks everyone out.
    s visudo -c -f "$T" >/dev/null
    s install -m 440 -o root -g root "$T" "/etc/sudoers.d/$TU"
    rm -f "$T"
    echo "SUDO_OK"
fi

HOMEDIR=$(getent passwd "$TU" | cut -d: -f6)
[ -n "$HOMEDIR" ] || HOMEDIR="/home/$TU"

KT=$(mktemp)
printf '%s' "$PUBKEY_B64" | base64 -d > "$KT"
s mkdir -p "$HOMEDIR/.ssh"
AK="$HOMEDIR/.ssh/authorized_keys"
# Repairs damage from an older version of this script that could fuse two
# keys onto one line (see comment at the Phase 1 sanitize step). No-op on
# an already-healthy file.
s sh -c "touch '$AK'; sed -i 's/ssh-ed25519/\n&/g; s/ssh-rsa/\n&/g' '$AK'; sed -i '/^\$/d' '$AK'; printf '\n' >> '$AK'; cat '$KT' >> '$AK'; printf '\n' >> '$AK'"
rm -f "$KT"
s chmod 700 "$HOMEDIR/.ssh"
s chmod 600 "$HOMEDIR/.ssh/authorized_keys"
s chown -R "$TU:$TU" "$HOMEDIR/.ssh"
echo "KEY_INSTALLED"
'@

$remoteScript = $remoteScript.Replace('{{TARGET_USER}}', $TargetUser).
                              Replace('{{PUBKEY_B64}}',  $PubKeyB64).
                              Replace('{{CREATE_USER}}', $(if ($CreateUser) { 'yes' } else { 'no' })).
                              Replace('{{ADD_SUDO}}',    $(if ($AddSudo)    { 'yes' } else { 'no' }))

# Normalise to LF - CRLF in a bash script is a classic silent failure.
$remoteScript = $remoteScript -replace "`r`n", "`n"
$ScriptB64    = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($remoteScript))

Write-Host ''
Write-Host "Phase 2: provisioning '$TargetUser'..." -ForegroundColor Cyan

$runner = "umask 077; T=`$(mktemp); echo $ScriptB64 | base64 -d > `$T; bash `$T; rc=`$?; rm -f `$T; exit `$rc"

$r2 = Invoke-Ssh ($CommonOpts + @('-i', $KeyPath, '-o', 'BatchMode=yes', "$AdminUser@$TargetHost", $runner)) -StdIn $SudoPass
$r2.Output | Out-Host
if ($r2.ExitCode -ne 0 -or $r2.Text -notmatch 'KEY_INSTALLED') {
    throw "Phase 2 failed (exit $($r2.ExitCode)). See output above."
}

# ── Verify: log in AS the target user, with the key only ───────────────────────
Write-Host ''
Write-Host 'Verifying key-only login as the target user...' -ForegroundColor Cyan
$check = if ($AddSudo) { 'whoami && sudo -n whoami' } else { 'whoami' }
$v    = Invoke-Ssh ($CommonOpts + @('-i', $KeyPath, '-o', 'BatchMode=yes', "$TargetUser@$TargetHost", $check))
$vTxt = $v.Text.Trim()

if ($vTxt -match [regex]::Escape($TargetUser)) {
    Write-Host "  Login OK as $TargetUser" -ForegroundColor Green
    if ($AddSudo) {
        if ($vTxt -match 'root') {
            Write-Host '  Passwordless sudo OK' -ForegroundColor Green
        } else {
            Write-Host '  WARNING: passwordless sudo did NOT verify.' -ForegroundColor Red
        }
    }
} else {
    Write-Host "  WARNING: verification failed: $vTxt" -ForegroundColor Red
}

# ── Cleanup ──────────────────────────────────────────────────────────
if ($TempKnownHosts -ne '' -and (Test-Path $TempKnownHosts)) {
    Remove-Item $TempKnownHosts -Force -ErrorAction SilentlyContinue
}

# ── Usage summary ──────────────────────────────────────────────────────────────
$sep      = '=' * 69
$optsText = if ($LegacyOpts.Count) { ' ' + ($LegacyOpts -join ' ') } else { '' }
$sshCmd   = 'ssh -i "' + $KeyPath + '"' + $optsText + ' ' + $TargetUser + '@' + $TargetHost

Write-Host ''
Write-Host $sep -ForegroundColor Cyan
Write-Host ' Setup complete' -ForegroundColor Green
Write-Host $sep -ForegroundColor Cyan
Write-Host ''
Write-Host "  Purpose    : $Purpose"
Write-Host "  Host       : $TargetHost"
Write-Host "  User       : $TargetUser"
Write-Host "  Key type   : $KeyType"
Write-Host "  Private key: $KeyPath"
Write-Host ''
Write-Host '  Connect with:' -ForegroundColor Yellow
Write-Host "    $sshCmd"
Write-Host ''
Write-Host '  Add to ~/.ssh/config for shorthand access:' -ForegroundColor Yellow
Write-Host "    Host $SafePurpose"
Write-Host "        HostName     $TargetHost"
Write-Host "        User         $TargetUser"
Write-Host "        IdentityFile $KeyPath"
Write-Host "        Port         $TargetPort"
if ($LegacyOpts.Count) {
    Write-Host "        PubkeyAcceptedKeyTypes +ssh-rsa"
    Write-Host "        HostKeyAlgorithms      +ssh-rsa"
}
Write-Host ''
Write-Host "  Then just: ssh $SafePurpose"
if ($StaleFixCmds.Count) {
    Write-Host ''
    Write-Host '  NOTE: the stale host key entry was left in place, so the commands above' -ForegroundColor Yellow
    Write-Host '  will fail with "REMOTE HOST IDENTIFICATION HAS CHANGED" until you run:' -ForegroundColor Yellow
    foreach ($n in $StaleFixCmds) { Write-Host "    ssh-keygen -R $n" }
}
Write-Host $sep
