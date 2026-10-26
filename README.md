# ssh-agent-access

Two scripts with the same job: set up key-only SSH access to a Debian or Ubuntu machine for an automated agent.

- `setup-ssh-agent-access.ps1`: for Windows, using the built-in OpenSSH client.
- `setup-ssh-agent-access.sh`: for bash, on Linux or WSL.

Both do the same steps:

1. Generate a named keypair. The key type is ed25519, or RSA-4096 for servers older than OpenSSH 6.5.
2. Connect with an existing admin account (one password prompt) and install the public key.
3. Optionally create the target user, and optionally give it passwordless sudo. The sudoers file is checked with `visudo` before it's installed.
4. Log in as the target user with the key only, to confirm it works. Print the `ssh` command and an `~/.ssh/config` snippet.

The sudo password goes to the remote host on stdin, never on a command line or in a file. In the bash version it sits in the remote shell's environment for the length of the run, which is visible to that user and to root.

## Requirements

- PowerShell script: Windows 10 or 11 with the OpenSSH client (`ssh.exe`, `ssh-keygen.exe`), PowerShell 5.1 or later. No modules.
- Bash script: bash, `ssh`, `ssh-keygen` and GNU `base64`.
- An existing admin account on the target, with a password or key.

## Usage

PowerShell:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\setup-ssh-agent-access.ps1
```

Bash:

```bash
bash setup-ssh-agent-access.sh
```

Both prompt for everything. Answer yes to passwordless sudo only for an agent that really needs root. A passwordless sudo account is full root for whoever holds its key.

## Differences

- The PowerShell script can remove a stale host key entry for you, or ignore host keys for one run. The bash script stops and prints the `ssh-keygen -R` command for you to run.

## Testing

Both were checked against a simulated host, not a real machine. The bash script was run against a fake `ssh` that logged every argument and stdin. The checks: the sudo password appears in no command line, it arrives on stdin, the remote script it sends is valid and sets the right user, and the key is installed. The PowerShell script parses but hasn't been run. Test both against a disposable Ubuntu or Debian VM before relying on them.

## Status

No license file yet, so all rights are reserved.
