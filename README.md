# pi-ssh

Run pi locally, work on files remotely over SSH.

`pi-ssh` is a pi extension that gives you a Cursor-like remote SSH workflow:

- pi runs on your local machine
- model access, API keys, and billing stay local
- `read`, `write`, `edit`, and `bash` run on a remote host via SSH

This is a **fork** with several fixes and improvements over the original.

## Fork improvements

- **No `.bash_history` pollution** — `HISTFILE=/dev/null` is set in the persistent shell init, so remote commands (marker lines, `cd`, the actual commands you send) never get written to the remote user's shell history. The original version wrote entries like `eval "$(printf '%s' ...| base64 -d)"` and `printf '__PI_SSH_BEGIN_...__\n'` to `.bash_history`.
- **No eval, no remote base64** — Multi-line commands now use a heredoc (`bash <<'EOF'`) instead of base64-encoding plus `eval`. This avoids eval entirely, removes the dependency on `base64` being present on the remote host, and makes debugging easier since commands appear verbatim.
- **SSH resume on `/resume`** — SSH connection parameters are persisted in the session via `pi.appendEntry()`. When you run `pi` elsewhere and `/resume` an SSH session, the extension automatically reconnects to the remote host. No need to re-pass `--ssh` on resume.
  - Resume failures (unreachable host, network change) show a warning instead of crashing — you still get local mode to browse the conversation.
- **Ctrl-C / Escape cancel actually works** — Pressing Escape to cancel a running remote command now kills the SSH connection, which reliably terminates the remote session (SIGHUP through the PTY cleans up child processes). The original version sent `\x03` (Ctrl-C byte) through a pipe-connected SSH stdin, which was unreliable — the byte often didn't reach the remote process because stdin was a pipe, not a terminal. On the next command, the extension reconnects automatically.

## Why

This is useful when:

- your code/checkouts live on a VM
- your model/tooling access is easier locally
- you want one local account to drive many remote workspaces

## Features

- `--ssh user@host` or `--ssh user@host:/remote/path`
- optional port override: `--ssh-port 2222` (alias: `-p 2222`)
- Remote tool delegation for:
  - `read`
  - `write`
  - `edit`
  - `bash`
- SSH connection multiplexing (`ControlMaster`/`ControlPersist`) for faster repeated tool calls
- Persistent remote shell session for bash commands
  - uses your remote account's configured login shell (for example zsh)
  - environment persists across commands (for example `export TEST=123`)
  - Ctrl-C interrupts the current remote command but keeps the SSH shell alive
  - **No `.bash_history` pollution** — `HISTFILE=/dev/null` on the remote shell
- Remote execution for user `!` commands
- Status indicator in the pi UI when SSH mode is active
- System prompt cwd rewrite to reflect remote cwd
- **Session resume** — `/resume` an SSH session and the extension reconnects automatically
- **Ctrl-C cancel works** — Escape properly interrupts the remote command without hanging

## Requirements

- SSH client installed locally
- Passwordless SSH auth recommended (keys/agent)
- Remote host with:
  - a standard login shell (for example `zsh` or `bash`)
  - `cat`, `test`, `mkdir`, `pwd`
  - optional: `file` (for image mime detection)

## Install

### Option A: project-local extension

```bash
mkdir -p .pi/extensions
cp /path/to/pi-ssh/index.ts .pi/extensions/pi-ssh.ts
```

Then start pi in your project and pass `--ssh`.

### Option B: global extension

```bash
mkdir -p ~/.pi/agent/extensions
cp /path/to/pi-ssh/index.ts ~/.pi/agent/extensions/pi-ssh.ts
```

## Usage

### Use remote host default cwd

```bash
pi --ssh user@my-vm
# optionally override the SSH-config/default port
pi --ssh user@my-vm --ssh-port 22
```

### Use explicit remote workspace path

```bash
pi --ssh user@my-vm:/home/user/chromium/src
# custom port
pi --ssh user@my-vm:/home/user/chromium/src -p 2222
```

You should see a status line similar to:

```text
SSH user@my-vm:/home/user/chromium/src (port ssh-config/default)
```

## Typical workflow

1. Start pi locally with `--ssh ...`
2. Ask pi to inspect/edit files as usual
3. All tool operations run remotely
4. Keep local model switching, auth, and limits as usual

## Notes

- Absolute paths are strongly recommended for the remote path.
- Paths under local `$HOME` are mapped to remote `$HOME` in SSH mode (for example `~/.config/...`).
- If `--ssh` is not set, extension falls back to local tool behavior.
- Current version focuses on core coding tools (`read/write/edit/bash`).

## Troubleshooting

### "pi-ssh failed to connect"

Check:

```bash
ssh user@host
ssh user@host 'pwd'
```

### Commands work locally but not remotely

Verify remote shell tools exist:

```bash
ssh user@host 'which cat test mkdir pwd'
```

### Slow tool calls

`bash`/`!` and most `read`/`write`/`edit` operations use a shared persistent SSH session.
Very large writes fall back to one-shot SSH streaming for reliability.

## Development

- Spec: `extension-spec.md`
- Extension entry: `index.ts`

## License

MIT
