# pi-ssh

Run pi locally, work on files remotely over SSH.

`pi-ssh` is a pi extension that gives you a Cursor-like remote SSH workflow:

- pi runs on your local machine
- model access, API keys, and billing stay local
- `read`, `write`, `edit`, and `bash` run on a remote host via SSH

This is a **fork** with several fixes and improvements over the original — see
[Fork improvements](#fork-improvements) below.

## Why

This is useful when:

- your code/checkouts live on a VM
- your model/tooling access is easier locally
- you want one local account to drive many remote workspaces

## Features

- `--ssh user@host` or `--ssh user@host:/remote/path` at startup
- `/ssh` command to connect, switch, or disconnect mid-session (no `--ssh` needed)
- optional port override: `--ssh-port 2222` (alias: `-p 2222`)
- Dedicated remote tools that the agent uses for remote work:
  - `ssh_read`
  - `ssh_write`
  - `ssh_edit`
  - `ssh_bash`
- The built-in `read`/`write`/`edit`/`bash` tools are left untouched and keep
  operating locally, so pi-ssh **coexists with extensions that own those names**
  (for example `pi-read-map`'s `read` or `pi-sandbox`'s `bash`). The agent is
  told via the system prompt to use the `ssh_*` tools for the remote workspace.
- SSH connection multiplexing (`ControlMaster`/`ControlPersist`) for faster repeated tool calls
- Persistent remote shell session for `ssh_bash`
  - uses your remote account's configured login shell (for example zsh)
  - environment persists across commands (for example `export TEST=123`)
  - Ctrl-C interrupts the current remote command but keeps the SSH shell alive
  - **No `.bash_history` pollution** — `HISTFILE=/dev/null` on the remote shell
- Remote execution for user `!` commands
- Status indicator in the pi UI when SSH mode is active
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

### Connect from the prompt with `/ssh`

You don't have to decide at startup. Run `/ssh` mid-session to connect, switch,
or disconnect — no `--ssh` flag required:

```text
/ssh                       pick a host from ~/.ssh/config
/ssh my-vm                 connect to a ~/.ssh/config host (or user@host)
/ssh user@my-vm:/path      connect with an explicit remote workspace path
/ssh user@my-vm:/path 2222 optional trailing port override
/ssh status                show the active connection
/ssh off                   disconnect (local tools only)
```

`/ssh` with no arguments offers the `Host` entries from your `~/.ssh/config`.
Connecting mid-session immediately enables the `ssh_*` tools; `/ssh off` tears
the connection down and leaves only the local tools.

## Typical workflow

1. Start pi locally (optionally with `--ssh ...`, or connect later with `/ssh`)
2. Ask pi to inspect/edit files on the remote — the agent uses the `ssh_*` tools
3. Use `!` for quick remote shell commands
4. Keep local model switching, auth, and limits as usual

## Notes

- Absolute paths are strongly recommended for the remote path.
- The built-in `read`/`write`/`edit`/`bash` tools stay local; remote work is done
  through `ssh_read`/`ssh_write`/`ssh_edit`/`ssh_bash`.
- Relative paths passed to `ssh_*` tools resolve against the remote cwd; remote
  absolute paths are used as-is. Paths under local `$HOME` map to remote `$HOME`.
- If `--ssh` is not set (and no SSH session is resumed), the `ssh_*` tools return
  an error telling you to connect; the built-in local tools are unaffected.
- Current version focuses on core coding tools (`ssh_read/ssh_write/ssh_edit/ssh_bash`).

## Security model

`pi-ssh` assumes **you trust the remote host you connect to**. In particular:

- The `ssh_*` tool operations and your `!` commands execute on the remote with
  your remote credentials. Only `--ssh` to hosts you control or trust.
- A remote `AGENTS.md` or `CLAUDE.md` in the remote cwd is loaded and injected
  into the agent's system prompt as project instructions — exactly as the local
  equivalents are. This means a **malicious remote repo can influence the agent
  via those files** (prompt injection). Treat the remote project as you would
  any code you run: don't point `pi-ssh` at untrusted hosts or repos.
- Host keys use `StrictHostKeyChecking=accept-new` (unknown hosts are pinned on
  first connect; a changed key is refused as a possible MITM).
- The SSH control socket lives in a per-user `0700` directory
  (`$XDG_RUNTIME_DIR/pi-ssh`, falling back to `~/.ssh/pi-ssh`), not in shared
  `/tmp`.

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

## Fork improvements

This is a fork of [hjanuschka/pi-ssh](https://github.com/hjanuschka/pi-ssh) with
the following fixes and improvements over the original:

- **No `.bash_history` pollution** — `HISTFILE=/dev/null` is set in the persistent shell init, so remote commands (marker lines, `cd`, the actual commands you send) never get written to the remote user's shell history. The original version wrote entries like `eval "$(printf '%s' ...| base64 -d)"` and `printf '__PI_SSH_BEGIN_...__\n'` to `.bash_history`.
- **No eval, no remote base64** — Multi-line commands now use a heredoc (`bash <<'EOF'`) instead of base64-encoding plus `eval`. This avoids eval entirely, removes the dependency on `base64` being present on the remote host, and makes debugging easier since commands appear verbatim.
- **SSH resume on `/resume`** — SSH connection parameters are persisted in the session via `pi.appendEntry()`. When you run `pi` elsewhere and `/resume` an SSH session, the extension automatically reconnects to the remote host. No need to re-pass `--ssh` on resume.
  - Resume failures (unreachable host, network change) show a warning instead of crashing — you still get local mode to browse the conversation.
- **Ctrl-C / Escape cancel actually works** — Pressing Escape to cancel a running remote command now kills the SSH connection, which reliably terminates the remote session (SIGHUP through the PTY cleans up child processes). The original version sent `\x03` (Ctrl-C byte) through a pipe-connected SSH stdin, which was unreliable — the byte often didn't reach the remote process because stdin was a pipe, not a terminal. On the next command, the extension reconnects automatically.
- **Security hardening** — non-world-writable control socket, explicit `StrictHostKeyChecking=accept-new` / `BatchMode=yes`, argv option-injection guards, and CSPRNG marker nonces (see [Security model](#security-model)).
- **Coexists with other tool extensions** — registers dedicated `ssh_read`/`ssh_write`/`ssh_edit`/`ssh_bash` tools instead of overriding the built-in `read`/`write`/`edit`/`bash`. The original overrode the built-ins, which fails to load alongside any extension that also owns those names (e.g. `pi-read-map`, `pi-sandbox`).
- **`/ssh` command** — connect, switch, or disconnect from a remote mid-session without restarting pi or passing `--ssh`, with a `~/.ssh/config` host picker (style inspired by [`pi-ssh-tools`](https://github.com/ogulcancelik/pi-extensions/tree/main/packages/pi-ssh-tools)).

## Development

- Spec: `extension-spec.md`
- Extension entry: `index.ts`

## License

MIT
