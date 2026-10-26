# ssh-agent-access

`setup-ssh-agent-access.ps1` sets up key-only SSH access to a Debian or Ubuntu machine for an automated agent. It:

1. Generates a named keypair on the Windows machine. The key type is ed25519, or RSA-4096 for servers older than OpenSSH 6.5.
2. Connects with an existing admin account, which asks for a password once, and installs the public key.
3. Optionally creates the target user, and optionally gives that user passwordless sudo. The sudoers file is checked with `visudo` before it's installed.
4. Logs in as the target user with the key only, to confirm it works. Prints the `ssh` command and an `~/.ssh/config` snippet.

The sudo password is passed to the remote host on stdin, so it never appears in the process list or in a file.

## Requirements

- Windows 10 or 11, with the OpenSSH client (`ssh.exe`, `ssh-keygen.exe`) installed. No PowerShell modules are needed.
- PowerShell 5.1 or later.
- An existing admin account on the target, with a password or key.

## Usage

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\setup-ssh-agent-access.ps1
```

The script prompts for everything. Answer `y` to "Add to passwordless sudoers" only for an agent that really needs root. A passwordless sudo account is full root for whoever holds its key.

## Notes

- If a reused address still has an old host key, the script stops and offers to remove the stale entry. Only accept if you know the machine was rebuilt.
- Not tested end to end from this copy. The script parses cleanly, and it was written against Ubuntu 24.04 and older Debian/TurnKey hosts.

## Status

No license file yet, so all rights are reserved.
