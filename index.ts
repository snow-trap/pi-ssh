import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { CustomEntry, ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
  createBashTool,
  createBashToolDefinition,
  createEditTool,
  createEditToolDefinition,
  createReadTool,
  createReadToolDefinition,
  createWriteTool,
  createWriteToolDefinition,
  type BashOperations,
  type EditOperations,
  type ReadOperations,
  type WriteOperations,
} from "@earendil-works/pi-coding-agent";

interface SshStoredConfig {
  remote: string;
  port?: number;
  remoteCwd: string;
  remoteHome: string;
}

interface SshConnection {
  remote: string;
  port?: number;
  remoteCwd: string;
  remoteHome: string;
  localCwd: string;
  localHome: string;
}

interface SshCaptureOptions {
  stdin?: string | Buffer;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

interface RunningCommand {
  startMarker: string;
  endMarker: string;
  timeout?: number;
  onData: (chunk: Buffer) => void;
  signal?: AbortSignal;
  aborted: boolean;
  timedOut: boolean;
  timeoutHandle?: NodeJS.Timeout;
  abortHandler?: () => void;
  stdoutChunks: Buffer[];
  stderrChunks: Buffer[];
  resolve: (value: { exitCode: number | null }) => void;
  reject: (error: Error) => void;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

// Cryptographically strong, unguessable nonce for command/heredoc markers.
// The remote shell echoes the command (and thus the marker) before output is
// produced, so a malicious remote that could predict the marker might emit a
// fake "__PI_SSH_DONE_<nonce>__:0" line to spoof success or truncate output.
// 128 bits of CSPRNG entropy removes that predictability.
function generateNonce(): string {
  return randomBytes(16).toString("hex");
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function parseDelimitedShellOutput(
  stdoutText: string,
  startMarker: string,
  endMarker: string,
): { output: string; exitCode: number | null } | null {
  const text = stdoutText.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

  const endRegex = new RegExp(`(^|\\n)${escapeRegex(endMarker)}:(-?\\d+)(?=\\n|$)`);
  const endMatch = endRegex.exec(text);
  if (!endMatch) {
    return null;
  }

  const endLineStart = endMatch.index + endMatch[1].length;

  const startRegex = new RegExp(`(^|\\n)${escapeRegex(startMarker)}(?=\\n|$)`, "g");
  let startLineEnd = 0;
  let foundStart = false;
  while (true) {
    const startMatch = startRegex.exec(text);
    if (!startMatch) break;

    const startLineStart = startMatch.index + startMatch[1].length;
    if (startLineStart >= endLineStart) break;

    foundStart = true;
    startLineEnd = startLineStart + startMarker.length;
    if (text[startLineEnd] === "\n") {
      startLineEnd += 1;
    }
  }

  if (!foundStart) {
    return null;
  }

  const output = text.slice(startLineEnd, endLineStart);
  const parsedExitCode = Number(endMatch[2]);
  const exitCode = Number.isNaN(parsedExitCode) ? null : parsedExitCode;
  return { output, exitCode };
}

class CommandQueue {
  private tail: Promise<void> = Promise.resolve();

  enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = this.tail.then(task, task);
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

function mapLocalPathToRemote(path: string, conn: SshConnection): string {
  if (path === conn.localCwd) return conn.remoteCwd;
  if (path.startsWith(`${conn.localCwd}/`)) {
    return `${conn.remoteCwd}${path.slice(conn.localCwd.length)}`;
  }
  if (path === conn.localHome) return conn.remoteHome;
  if (path.startsWith(`${conn.localHome}/`)) {
    return `${conn.remoteHome}${path.slice(conn.localHome.length)}`;
  }
  return path;
}

function findRemotePathSeparator(value: string): number {
  const colonIndex = value.lastIndexOf(":");
  if (colonIndex === -1) {
    return -1;
  }

  const remotePath = value.slice(colonIndex + 1).trim();
  if (remotePath.startsWith("/") || remotePath === "~" || remotePath.startsWith("~/")) {
    return colonIndex;
  }

  // Preserve host:relative-path for the common single-colon form, but avoid
  // mis-parsing IPv6 literals without an explicit remote path.
  if (value.indexOf(":") === colonIndex) {
    return colonIndex;
  }

  return -1;
}

// Guard against argv option-injection: ssh treats any argument starting with
// "-" as an option, so a host like "-oProxyCommand=..." would run a local
// command. Reject leading dashes; legitimate hosts never start with one.
function assertSafeRemote(remote: string): void {
  if (remote.startsWith("-")) {
    throw new Error(`Invalid SSH remote (must not start with "-"): ${remote}`);
  }
}

function parseSshFlag(raw: string): { remote: string; remotePath?: string } {
  const value = raw.trim();
  if (!value) {
    throw new Error("--ssh requires a value like user@host or user@host:/remote/path");
  }

  const colonIndex = findRemotePathSeparator(value);
  if (colonIndex === -1) {
    assertSafeRemote(value);
    return { remote: value };
  }

  const remote = value.slice(0, colonIndex).trim();
  const remotePath = value.slice(colonIndex + 1).trim();
  if (!remote) {
    throw new Error("Invalid --ssh value: missing remote host");
  }
  if (!remotePath) {
    throw new Error("Invalid --ssh value: empty remote path");
  }
  assertSafeRemote(remote);
  return { remote, remotePath };
}

// Parse `Host` aliases from ~/.ssh/config for the `/ssh` picker and argument
// completions. Wildcard / negated patterns are skipped — they aren't directly
// connectable targets.
function readSshConfigHosts(): string[] {
  let text: string;
  try {
    text = readFileSync(join(homedir(), ".ssh", "config"), "utf-8");
  } catch {
    return [];
  }

  const hosts: string[] = [];
  for (const line of text.split("\n")) {
    const match = /^\s*Host\s+(.+?)\s*$/i.exec(line);
    if (!match) continue;
    for (const token of match[1].split(/\s+/)) {
      if (!token || token.includes("*") || token.includes("?") || token.startsWith("!")) continue;
      if (!hosts.includes(token)) hosts.push(token);
    }
  }
  return hosts;
}

function parseSshPort(raw: string | undefined): number | undefined {
  if (raw === undefined) {
    return undefined;
  }

  const value = raw.trim();
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`Invalid SSH port: ${value}`);
  }
  return parsed;
}

// Resolve a per-user, non-world-writable directory for the SSH ControlPath
// socket. A predictable socket in shared /tmp lets other local users probe
// session existence and invites symlink/race issues, so prefer $XDG_RUNTIME_DIR
// (already 0700) and fall back to a 0700 dir under $HOME. Computed once and
// created eagerly; failures fall back to /tmp rather than breaking SSH.
function resolveControlDir(): string {
  const candidates = [process.env.XDG_RUNTIME_DIR, homedir() ? join(homedir(), ".ssh") : undefined].filter(
    (value): value is string => Boolean(value),
  );

  for (const base of candidates) {
    const dir = join(base, "pi-ssh");
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      return dir;
    } catch {
      // try next candidate
    }
  }

  return "/tmp";
}

const CONTROL_SOCKET_DIR = resolveControlDir();

function buildSshBaseArgs(port?: number): string[] {
  const args: string[] = [];
  if (port !== undefined) {
    args.push("-p", String(port));
  }

  args.push(
    // Own the security posture explicitly instead of inheriting ambient
    // ~/.ssh/config: accept-new pins unknown hosts on first use but refuses
    // changed keys (MITM), and BatchMode prevents a piped, non-interactive
    // ssh from hanging forever on an auth/host-key prompt.
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "BatchMode=yes",
    "-o",
    "ControlMaster=auto",
    "-o",
    "ControlPersist=600",
    "-o",
    `ControlPath=${join(CONTROL_SOCKET_DIR, "cm-%C")}`,
  );

  return args;
}

function buildResolveRemotePathCommand(remotePath: string): string {
  if (remotePath === "~") {
    return 'cd -- "$HOME" && pwd';
  }
  if (remotePath.startsWith("~/")) {
    return `cd -- "$HOME"/${shellQuote(remotePath.slice(2))} && pwd`;
  }
  return `cd -- ${shellQuote(remotePath)} && pwd`;
}

async function sshCapture(
  remote: string,
  port: number | undefined,
  remoteCommand: string,
  options: SshCaptureOptions = {},
): Promise<{ stdout: Buffer; stderr: Buffer; exitCode: number | null; timedOut: boolean }> {
  return new Promise((resolve, reject) => {
    const child = spawn("ssh", [...buildSshBaseArgs(port), "--", remote, remoteCommand], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let timedOut = false;

    const timeoutHandle =
      options.timeoutSeconds && options.timeoutSeconds > 0
        ? setTimeout(() => {
            timedOut = true;
            child.kill();
          }, options.timeoutSeconds * 1000)
        : undefined;

    const onAbort = () => child.kill();
    if (options.signal) {
      if (options.signal.aborted) {
        child.kill();
      } else {
        options.signal.addEventListener("abort", onAbort, { once: true });
      }
    }

    child.on("error", (error) => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      if (options.signal) options.signal.removeEventListener("abort", onAbort);
      reject(error);
    });

    child.stdout.on("data", (chunk) => stdoutChunks.push(chunk));
    child.stderr.on("data", (chunk) => stderrChunks.push(chunk));

    child.on("close", (exitCode) => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      if (options.signal) options.signal.removeEventListener("abort", onAbort);
      resolve({
        stdout: Buffer.concat(stdoutChunks),
        stderr: Buffer.concat(stderrChunks),
        exitCode,
        timedOut,
      });
    });

    if (options.stdin !== undefined) {
      child.stdin.write(options.stdin);
    }
    child.stdin.end();
  });
}

async function sshExec(remote: string, port: number | undefined, remoteCommand: string, options: SshCaptureOptions = {}): Promise<Buffer> {
  const result = await sshCapture(remote, port, remoteCommand, options);
  if (result.timedOut) {
    throw new Error(`SSH command timed out after ${options.timeoutSeconds ?? 0}s`);
  }
  if (result.exitCode !== 0) {
    const stderr = result.stderr.toString("utf-8").trim();
    const message = stderr || `SSH command failed with exit code ${result.exitCode}`;
    throw new Error(message);
  }
  return result.stdout;
}

// Default timeout (5 minutes) prevents a single hung command from blocking
// the entire SSH command queue forever.
const DEFAULT_EXEC_TIMEOUT_SECONDS = 300;

class PersistentRemoteShell {
  private connection: SshConnection;
  private child: ChildProcessWithoutNullStreams | null = null;
  private running: RunningCommand | null = null;
  private disposed = false;
  private startupPromise: Promise<void> | null = null;
  // Incremental streaming state: tracks how many bytes of the normalized
  // (post-start-marker) output have already been sent via onData.
  private streamedBytes = 0;
  private seenStartMarker = false;
  // Position in the raw stdout text right after the start marker line.
  private startMarkerEnd = 0;

  constructor(connection: SshConnection) {
    this.connection = connection;
  }

  async dispose(): Promise<void> {
    this.disposed = true;
    if (this.running) {
      this.running.reject(new Error("Remote shell disposed"));
      this.running = null;
    }
    if (this.child && !this.child.killed) {
      this.child.kill();
    }
    this.child = null;
  }

  exec(command: string, cwd: string, options: { onData: (data: Buffer) => void; signal?: AbortSignal; timeout?: number }): Promise<{ exitCode: number | null }> {
    return this.execOne(command, cwd, options);
  }

  private async ensureStarted(): Promise<void> {
    if (this.disposed) {
      throw new Error("Remote shell is disposed");
    }
    if (this.child && !this.child.killed) {
      if (this.startupPromise) {
        await this.startupPromise;
      }
      return;
    }
    if (this.startupPromise) {
      await this.startupPromise;
      return;
    }

    this.startupPromise = new Promise<void>((resolve, reject) => {
      const child = spawn("ssh", [...buildSshBaseArgs(this.connection.port), "-tt", "--", this.connection.remote], {
        stdio: ["pipe", "pipe", "pipe"],
      });

      let settled = false;
      const startupMarker = `__PI_SSH_READY_${generateNonce()}__`;
      const startupStdoutChunks: Buffer[] = [];
      const startupStderrChunks: Buffer[] = [];

      const finishResolve = () => {
        if (settled) return;
        settled = true;
        resolve();
      };

      const finishReject = (error: Error) => {
        if (settled) return;
        settled = true;
        reject(error);
      };

      child.on("error", (error) => {
        if (!settled) {
          finishReject(error instanceof Error ? error : new Error(String(error)));
          return;
        }
        if (this.running) {
          this.running.reject(error instanceof Error ? error : new Error(String(error)));
          this.cleanupRunning();
        }
      });

      child.on("close", () => {
        if (!settled) {
          const stderr = Buffer.concat(startupStderrChunks).toString("utf-8").trim();
          finishReject(new Error(stderr || "SSH shell closed during startup"));
          return;
        }
        if (this.running) {
          const reason = this.running.aborted ? "Command aborted" : "SSH shell closed unexpectedly";
          this.running.reject(new Error(reason));
          this.cleanupRunning();
        }
        this.child = null;
      });

      child.stdout.on("data", (chunk: Buffer) => {
        if (!settled) {
          startupStdoutChunks.push(chunk);
          const text = this.normalize(Buffer.concat(startupStdoutChunks).toString("utf-8"));
          if (text.includes(`${startupMarker}\n`)) {
            finishResolve();
            return;
          }
        }
        this.handleStdout(chunk);
      });

      child.stderr.on("data", (chunk: Buffer) => {
        if (!settled) {
          startupStderrChunks.push(chunk);
        }
        this.handleStderr(chunk);
      });

      this.child = child;
      this.child.stdin.write(
        "HISTFILE=/dev/null; trap '' INT; stty -echo 2>/dev/null || true; unset PROMPT_COMMAND 2>/dev/null || true; PS1=''; PS2=''; PROMPT=''; RPROMPT=''; " +
          "export PAGER=cat; export GIT_PAGER=cat; export GIT_TERMINAL_PROMPT=0; " +
          "if [ -n \"${ZSH_VERSION-}\" ]; then precmd_functions=(); preexec_functions=(); chpwd_functions=(); unset zle_bracketed_paste 2>/dev/null || true; fi; " +
          "if [ -n \"${BASH_VERSION-}\" ]; then bind 'set enable-bracketed-paste off' 2>/dev/null || true; fi; " +
          `cd -- ${shellQuote(this.connection.remoteCwd)}; printf '${startupMarker}\\n'\n`,
      );
    });

    try {
      await this.startupPromise;
    } finally {
      this.startupPromise = null;
    }
  }

  private handleStdout(chunk: Buffer): void {
    const running = this.running;
    if (!running) return;
    running.stdoutChunks.push(chunk);
    this.streamIncremental();
    this.tryCompleteRunning();
  }

  private handleStderr(chunk: Buffer): void {
    const running = this.running;
    if (!running) return;
    running.stderrChunks.push(chunk);
  }

  /**
   * Normalize raw PTY output the same way parseDelimitedShellOutput does.
   * Some remote shells emit bare carriage returns before prompt/control
   * sequences; treat those as line breaks so command markers are found.
   */
  private normalize(text: string): string {
    return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  }

  /**
   * Stream output incrementally to onData as it arrives, rather than
   * waiting for the command to complete. This enables live progress
   * in the TUI (tool_execution_update events).
   *
   * Works on normalized text so the bytes sent match parseDelimitedShellOutput
   * output exactly, allowing correct "remaining" calculation at completion.
   */
  private streamIncremental(): void {
    const running = this.running;
    if (!running) return;

    const rawText = Buffer.concat(running.stdoutChunks).toString("utf-8");
    const text = this.normalize(rawText);

    // Wait until we've seen the start marker before streaming anything
    if (!this.seenStartMarker) {
      const startRegex = new RegExp(`(^|\\n)${escapeRegex(running.startMarker)}\\n`);
      const startMatch = startRegex.exec(text);
      if (!startMatch) return;
      this.seenStartMarker = true;
      this.startMarkerEnd = startMatch.index + startMatch[0].length;
      this.streamedBytes = 0;
    }

    // Extract the output region: everything after the start marker
    const outputSoFar = text.slice(this.startMarkerEnd);

    // Hold back the last 1-2 lines to avoid streaming partial end markers.
    // The end marker looks like: __PI_SSH_DONE_<id>__:<exitcode>
    // Find the last newline that's safe to stream up to.
    const endMarkerPrefix = "__PI_SSH_DONE_";
    let safeLen = outputSoFar.length;

    // Walk back from the end to find lines that might be (partial) end markers
    const lastNl = outputSoFar.lastIndexOf("\n");
    if (lastNl >= 0) {
      const tailLine = outputSoFar.slice(lastNl + 1);
      if (tailLine.length === 0 || tailLine.includes(endMarkerPrefix) || endMarkerPrefix.startsWith(tailLine.trimEnd())) {
        // The incomplete last line might be a marker; hold it back
        safeLen = lastNl + 1;
      }
      // Also check the last complete line
      if (safeLen === lastNl + 1) {
        const prevNl = outputSoFar.lastIndexOf("\n", lastNl - 1);
        const lastCompleteLine = outputSoFar.slice(prevNl + 1, lastNl);
        if (lastCompleteLine.includes(endMarkerPrefix)) {
          safeLen = Math.max(0, prevNl + 1);
        }
      }
    } else {
      // No newline at all yet — could be a partial marker, hold everything back
      if (outputSoFar.includes(endMarkerPrefix) || endMarkerPrefix.startsWith(outputSoFar.trimEnd())) {
        safeLen = 0;
      }
    }

    if (safeLen > this.streamedBytes) {
      const newData = outputSoFar.slice(this.streamedBytes, safeLen);
      if (newData.length > 0) {
        running.onData(Buffer.from(newData, "utf-8"));
        this.streamedBytes = safeLen;
      }
    }
  }

  private tryCompleteRunning(): void {
    const running = this.running;
    if (!running) return;

    const rawText = Buffer.concat(running.stdoutChunks).toString("utf-8");
    const parsed = parseDelimitedShellOutput(rawText, running.startMarker, running.endMarker);
    if (!parsed) return;

    // parsed.output is the normalized output between markers.
    // Send any bytes we haven't streamed yet (the held-back tail).
    const fullOutput = parsed.output;
    if (this.streamedBytes < fullOutput.length) {
      const remaining = fullOutput.slice(this.streamedBytes);
      running.onData(Buffer.from(remaining, "utf-8"));
    }

    // Also send stderr (merged at the end, matching original behavior)
    const stderr = Buffer.concat(running.stderrChunks);
    if (stderr.length > 0) {
      running.onData(stderr);
    }

    const exitCode = parsed.exitCode;
    const timedOut = running.timedOut;
    const aborted = running.aborted;
    const timeout = running.timeout;

    this.cleanupRunning();

    if (timedOut) {
      running.reject(new Error(`timeout:${timeout}`));
      return;
    }
    if (aborted) {
      running.reject(new Error("aborted"));
      return;
    }

    running.resolve({ exitCode });
  }

  private cleanupRunning(): void {
    if (!this.running) return;
    if (this.running.timeoutHandle) clearTimeout(this.running.timeoutHandle);
    if (this.running.signal && this.running.abortHandler) {
      this.running.signal.removeEventListener("abort", this.running.abortHandler);
    }
    this.running = null;
  }

  private interruptCurrentCommand(): void {
    if (!this.child || this.child.killed) return;
    // Mark the running command as aborted so the close handler reports
    // "Command aborted" instead of "SSH shell closed unexpectedly".
    if (this.running) {
      this.running.aborted = true;
    }
    // Kill the SSH connection entirely. The close event fires, rejecting
    // the running promise. The next execOne() reconnects via ensureStarted().
    //
    // Sending \x03 through the PTY (Ctrl-C) is unreliable because:
    // - stdin is a pipe, not a terminal, so the SSH client may buffer or
    //   mishandle the byte
    // - the remote PTY's ISIG flag might be off
    // - the remote shell's SIGINT handling might not propagate to the child
    // Killing the SSH process is guaranteed to terminate the remote session
    // (SIGHUP through the PTY cleans up child processes on the remote side).
    this.child.kill("SIGTERM");
  }

  private async execOne(
    command: string,
    cwd: string,
    options: { onData: (data: Buffer) => void; signal?: AbortSignal; timeout?: number },
  ): Promise<{ exitCode: number | null }> {
    await this.ensureStarted();
    if (!this.child || this.child.killed) {
      throw new Error("Failed to start persistent SSH shell");
    }

    const unique = generateNonce();
    const startMarker = `__PI_SSH_BEGIN_${unique}__`;
    const endMarker = `__PI_SSH_DONE_${unique}__`;
    const remoteCwd = mapLocalPathToRemote(cwd, this.connection);

    // Redirect stdin from /dev/null so commands that accidentally read from
    // stdin (e.g., bare `wc`, `read`, `cat` without args) get EOF immediately
    // instead of blocking forever on the PTY. Shell pipelines still work
    // because the pipe overrides stdin for downstream commands.
    //
    // If the command contains newlines (e.g. multi-line git commit -m "..."),
    // a heredoc is used so the PTY sees the command as multi-line input
    // rather than separate command submissions. This avoids base64+eval
    // encoding entirely.
    const heredocMarker = `__PI_SSH_EOF_${unique}__`;
    const wrappedCommand = [
      `printf '${startMarker}\\n'`,
      `if cd -- ${shellQuote(remoteCwd)}; then`,
      `  bash <<'${heredocMarker}'`,
      // Keep the command on its own lines. Appending `; }` directly to a
      // command that ends with a heredoc changes its terminator from (for
      // example) `PY` to `PY; }`, so bash never recognizes the terminator.
      "{",
      command,
      "} </dev/null",
      heredocMarker,
      `  __pi_ec=$?`,
      `else`,
      `  __pi_ec=$?`,
      `fi`,
      `printf '\\n${endMarker}:%s\\n' "$__pi_ec"`,
    ].join("\n");

    // Reset incremental streaming state for the new command
    this.streamedBytes = 0;
    this.seenStartMarker = false;
    this.startMarkerEnd = 0;

    // Apply default timeout if none specified, so a hung command can't
    // block the queue forever
    const effectiveTimeout = options.timeout ?? DEFAULT_EXEC_TIMEOUT_SECONDS;

    return new Promise((resolve, reject) => {
      const running: RunningCommand = {
        startMarker,
        endMarker,
        timeout: effectiveTimeout,
        onData: options.onData,
        signal: options.signal,
        aborted: false,
        timedOut: false,
        stdoutChunks: [],
        stderrChunks: [],
        resolve,
        reject,
      };

      if (effectiveTimeout > 0) {
        running.timeoutHandle = setTimeout(() => {
          running.timedOut = true;
          this.interruptCurrentCommand();
        }, effectiveTimeout * 1000);
      }

      if (options.signal) {
        running.abortHandler = () => {
          running.aborted = true;
          this.interruptCurrentCommand();
        };

        if (options.signal.aborted) {
          running.abortHandler();
        } else {
          options.signal.addEventListener("abort", running.abortHandler, { once: true });
        }
      }

      this.running = running;
      this.child?.stdin.write(`${wrappedCommand}\n`);
    });
  }
}

const PERSISTENT_WRITE_MAX_BYTES = 256 * 1024;

interface RemoteTransport {
  dispose(): Promise<void>;
  exec(
    command: string,
    cwd: string,
    options: { onData: (data: Buffer) => void; signal?: AbortSignal; timeout?: number },
  ): Promise<{ exitCode: number | null }>;
  readFile(remotePath: string): Promise<Buffer>;
  ensureReadable(remotePath: string): Promise<void>;
  ensureReadableWritable(remotePath: string): Promise<void>;
  detectImageMimeType(remotePath: string): Promise<string | null>;
  mkdir(remoteDir: string): Promise<void>;
  writeFile(remotePath: string, content: Buffer): Promise<void>;
}

function remoteDirname(path: string): string {
  const slashIndex = path.lastIndexOf("/");
  if (slashIndex <= 0) return "/";
  return path.slice(0, slashIndex);
}

class SshTransport implements RemoteTransport {
  private connection: SshConnection;
  private shell: PersistentRemoteShell;
  private queue = new CommandQueue();

  constructor(connection: SshConnection) {
    this.connection = connection;
    this.shell = new PersistentRemoteShell(connection);
  }

  async dispose(): Promise<void> {
    await this.shell.dispose();
  }

  exec(
    command: string,
    cwd: string,
    options: { onData: (data: Buffer) => void; signal?: AbortSignal; timeout?: number },
  ): Promise<{ exitCode: number | null }> {
    return this.queue.enqueue(() => this.shell.exec(command, cwd, options));
  }

  async readFile(remotePath: string): Promise<Buffer> {
    // Read files over a one-shot SSH exec so bytes are preserved exactly.
    // The persistent shell runs through a PTY and normalizes output for
    // streaming, which is fine for text commands but corrupts binary reads.
    return this.queue.enqueue(() =>
      sshExec(this.connection.remote, this.connection.port, `cat -- ${shellQuote(remotePath)}`, {
        timeoutSeconds: DEFAULT_EXEC_TIMEOUT_SECONDS,
      }),
    );
  }

  async ensureReadable(remotePath: string): Promise<void> {
    await this.runChecked(`test -r ${shellQuote(remotePath)}`);
  }

  async ensureReadableWritable(remotePath: string): Promise<void> {
    await this.runChecked(`test -r ${shellQuote(remotePath)} && test -w ${shellQuote(remotePath)}`);
  }

  async detectImageMimeType(remotePath: string): Promise<string | null> {
    const result = await this.capture(`file --mime-type -b -- ${shellQuote(remotePath)} 2>/dev/null || true`);
    const mime = result.output.toString("utf-8").trim();
    if (["image/jpeg", "image/png", "image/gif", "image/webp"].includes(mime)) {
      return mime;
    }
    return null;
  }

  async mkdir(remoteDir: string): Promise<void> {
    await this.runChecked(`mkdir -p -- ${shellQuote(remoteDir)}`);
  }

  async writeFile(remotePath: string, content: Buffer): Promise<void> {
    if (content.length <= PERSISTENT_WRITE_MAX_BYTES) {
      const remoteDir = remoteDirname(remotePath);
      const encodedContent = content.toString("base64");
      const command = [
        `mkdir -p -- ${shellQuote(remoteDir)}`,
        `printf '%s' ${shellQuote(encodedContent)} | base64 -d > ${shellQuote(remotePath)}`,
      ].join(" && ");

      try {
        await this.runChecked(command);
        return;
      } catch {
        // fall through to one-shot streaming fallback
      }
    }

    await this.queue.enqueue(async () => {
      const remoteDir = remoteDirname(remotePath);
      const command = [`mkdir -p -- ${shellQuote(remoteDir)}`, `cat > ${shellQuote(remotePath)}`].join(" && ");
      await sshExec(this.connection.remote, this.connection.port, command, {
        stdin: content,
      });
    });
  }

  private async capture(
    command: string,
    options: { timeout?: number; signal?: AbortSignal } = {},
  ): Promise<{ exitCode: number | null; output: Buffer }> {
    return this.queue.enqueue(async () => {
      const outputChunks: Buffer[] = [];
      const result = await this.shell.exec(command, this.connection.localCwd, {
        timeout: options.timeout,
        signal: options.signal,
        onData: (data) => {
          outputChunks.push(data);
        },
      });
      return {
        exitCode: result.exitCode,
        output: Buffer.concat(outputChunks),
      };
    });
  }

  private async runChecked(command: string, timeout?: number): Promise<Buffer> {
    const result = await this.capture(command, { timeout });
    if (result.exitCode !== 0) {
      const stderr = result.output.toString("utf-8").trim();
      throw new Error(stderr || `SSH command failed with exit code ${result.exitCode}`);
    }
    return result.output;
  }
}

function createRemoteReadOps(conn: SshConnection, transport: RemoteTransport): ReadOperations {
  return {
    readFile: async (absolutePath) => {
      const remotePath = mapLocalPathToRemote(absolutePath, conn);
      return transport.readFile(remotePath);
    },
    access: async (absolutePath) => {
      const remotePath = mapLocalPathToRemote(absolutePath, conn);
      await transport.ensureReadable(remotePath);
    },
    detectImageMimeType: async (absolutePath) => {
      const remotePath = mapLocalPathToRemote(absolutePath, conn);
      try {
        return await transport.detectImageMimeType(remotePath);
      } catch {
        return null;
      }
    },
  };
}

function createRemoteWriteOps(conn: SshConnection, transport: RemoteTransport): WriteOperations {
  return {
    mkdir: async (absoluteDir) => {
      const remoteDir = mapLocalPathToRemote(absoluteDir, conn);
      await transport.mkdir(remoteDir);
    },
    writeFile: async (absolutePath, content) => {
      const remotePath = mapLocalPathToRemote(absolutePath, conn);
      await transport.writeFile(remotePath, Buffer.from(content, "utf-8"));
    },
  };
}

function createRemoteEditOps(conn: SshConnection, transport: RemoteTransport): EditOperations {
  const readOps = createRemoteReadOps(conn, transport);
  const writeOps = createRemoteWriteOps(conn, transport);

  return {
    readFile: readOps.readFile,
    writeFile: writeOps.writeFile,
    access: async (absolutePath) => {
      const remotePath = mapLocalPathToRemote(absolutePath, conn);
      await transport.ensureReadableWritable(remotePath);
    },
  };
}

function createRemoteBashOps(transport: RemoteTransport): BashOperations {
  return {
    exec: (command, cwd, { onData, signal, timeout }) => {
      return transport.exec(command, cwd, { onData, signal, timeout });
    },
  };
}

async function resolveSshConnection(rawFlag: string, localCwd: string, localHome: string, port: number | undefined): Promise<SshConnection> {
  const parsed = parseSshFlag(rawFlag);

  const remoteHomeBuffer = await sshExec(parsed.remote, port, 'printf "%s" "$HOME"', {
    timeoutSeconds: 15,
  });
  const remoteHome = remoteHomeBuffer.toString("utf-8").trim();

  if (!remoteHome) {
    throw new Error("Failed to detect remote HOME");
  }

  if (!parsed.remotePath) {
    const remotePwd = await sshExec(parsed.remote, port, "pwd", { timeoutSeconds: 15 });
    return {
      remote: parsed.remote,
      port,
      remoteCwd: remotePwd.toString("utf-8").trim(),
      remoteHome,
      localCwd,
      localHome,
    };
  }

  const resolvedPath = await sshExec(parsed.remote, port, buildResolveRemotePathCommand(parsed.remotePath), {
    timeoutSeconds: 15,
  });

  return {
    remote: parsed.remote,
    port,
    remoteCwd: resolvedPath.toString("utf-8").trim(),
    remoteHome,
    localCwd,
    localHome,
  };
}

export default function piSshExtension(pi: ExtensionAPI): void {
  pi.registerFlag("ssh", {
    description: "SSH target as user@host or user@host:/absolute/remote/path",
    type: "string",
  });
  pi.registerFlag("ssh-port", {
    description: "SSH port override (otherwise SSH config/defaults are used)",
    type: "string",
  });
  pi.registerFlag("p", {
    description: "Alias for --ssh-port",
    type: "string",
  });

  const localCwd = process.cwd();
  const localHome = homedir();

  const localRead = createReadTool(localCwd);
  const localWrite = createWriteTool(localCwd);
  const localEdit = createEditTool(localCwd);
  const localBash = createBashTool(localCwd);

  let connection: SshConnection | null = null;
  let transport: SshTransport | null = null;
  let remoteContextSection = "";

  const getConnection = () => connection;

  // Dedicated, uniquely-named remote tools instead of overriding the built-in
  // read/write/edit/bash. Overriding collides with any other extension that
  // also owns those names (e.g. pi-read-map's `read`, pi-sandbox's `bash`),
  // which pi rejects at load time. With ssh_* names, pi-ssh coexists with them:
  // the built-in/other-extension read/bash stay LOCAL, and remote work is
  // explicit via these tools.
  const requireSsh = (toolName: string): { conn: SshConnection; transport: SshTransport } => {
    const conn = getConnection();
    if (!conn || !transport) {
      throw new Error(
        `${toolName} requires an active SSH connection. Start pi with --ssh user@host[:/path], or run /ssh, or resume an SSH session.`,
      );
    }
    return { conn, transport };
  };

  // Load AGENTS.md / CLAUDE.md from the remote cwd into the system-prompt
  // section. Shared by startup, resume, and the /ssh command.
  const loadRemoteContext = async (ctx: ExtensionContext): Promise<void> => {
    remoteContextSection = "";
    if (!connection || !transport) return;
    try {
      for (const name of ["AGENTS.md", "CLAUDE.md"]) {
        try {
          const content = (await transport.readFile(`${connection.remoteCwd}/${name}`)).toString("utf-8").trim();
          if (content) {
            remoteContextSection = `\n\n# Remote Project Context\n\n## ${connection.remoteCwd}/${name}\n\n${content}\n`;
            if (ctx.hasUI) ctx.ui.notify(`Loaded remote context file: ${name}`, "info");
            break;
          }
        } catch {
          // not found, try next
        }
      }
    } catch {
      // skip context loading on error
    }
  };

  // Establish a connection from a resolved SshConnection, wiring up the
  // transport, optional resume persistence, status line, and remote context.
  const activateConnection = async (
    conn: SshConnection,
    ctx: ExtensionContext,
    opts: { persist: boolean; verb: string },
  ): Promise<void> => {
    if (transport) {
      await transport.dispose();
      transport = null;
    }
    connection = conn;
    transport = new SshTransport(conn);

    if (opts.persist) {
      // Persist config in session so /resume can re-establish the connection.
      pi.appendEntry("pi-ssh-config", {
        remote: conn.remote,
        port: conn.port,
        remoteCwd: conn.remoteCwd,
        remoteHome: conn.remoteHome,
      } satisfies SshStoredConfig);
    }

    const portLabel = conn.port ?? "ssh-config/default";
    const message = `pi-ssh ${opts.verb}: ${conn.remote}:${conn.remoteCwd} (port ${portLabel})`;
    console.log(message);
    if (ctx.hasUI) {
      ctx.ui.setStatus("pi-ssh", ctx.ui.theme.fg("accent", `SSH ${conn.remote}:${conn.remoteCwd} (port ${portLabel})`));
      ctx.ui.notify(message, "info");
    }

    await loadRemoteContext(ctx);
  };

  const deactivateConnection = async (ctx: ExtensionContext): Promise<void> => {
    if (transport) {
      await transport.dispose();
      transport = null;
    }
    connection = null;
    remoteContextSection = "";
    if (ctx.hasUI) ctx.ui.setStatus("pi-ssh", undefined);
  };

  // Spread the UNWRAPPED tool definitions (create*ToolDefinition) rather than the
  // wrapped AgentTools (create*Tool): wrapToolDefinition() strips renderCall and
  // renderResult, which is why ssh_* tools previously fell back to name-only
  // fallback rendering in the TUI. The renderers are pure functions of
  // args/result/details and do not touch operations, so they work unchanged for
  // remote results. promptSnippet/promptGuidelines are overridden because the
  // built-in ones name the local tools ("read", "write", ...), not ssh_*.
  pi.registerTool({
    ...createReadToolDefinition(localCwd),
    name: "ssh_read",
    label: "ssh_read",
    description: `Read a file on the remote SSH host. ${localRead.description}`,
    promptSnippet: "Read file contents on the remote SSH host",
    promptGuidelines: ["Use ssh_read to examine files on the remote SSH host instead of cat or sed via ssh_bash."],
    async execute(id, params, signal, onUpdate) {
      const { conn, transport } = requireSsh("ssh_read");
      const tool = createReadTool(localCwd, { operations: createRemoteReadOps(conn, transport) });
      return tool.execute(id, params, signal, onUpdate);
    },
  });

  pi.registerTool({
    ...createWriteToolDefinition(localCwd),
    name: "ssh_write",
    label: "ssh_write",
    description: `Write a file on the remote SSH host. ${localWrite.description}`,
    promptSnippet: "Create or overwrite files on the remote SSH host",
    promptGuidelines: ["Use ssh_write only for new files or complete rewrites on the remote SSH host."],
    async execute(id, params, signal, onUpdate) {
      const { conn, transport } = requireSsh("ssh_write");
      const tool = createWriteTool(localCwd, { operations: createRemoteWriteOps(conn, transport) });
      return tool.execute(id, params, signal, onUpdate);
    },
  });

  pi.registerTool({
    ...createEditToolDefinition(localCwd),
    name: "ssh_edit",
    label: "ssh_edit",
    description: `Edit a file on the remote SSH host. ${localEdit.description}`,
    promptSnippet: "Make precise edits to files on the remote SSH host with exact text replacement",
    promptGuidelines: [
      "Use ssh_edit for precise changes to files on the remote SSH host (edits[].oldText must match exactly)",
      "When changing multiple separate locations in one remote file, use one ssh_edit call with multiple entries in edits[] instead of multiple ssh_edit calls",
    ],
    async execute(id, params, signal, onUpdate) {
      const { conn, transport } = requireSsh("ssh_edit");
      const tool = createEditTool(localCwd, { operations: createRemoteEditOps(conn, transport) });
      return tool.execute(id, params, signal, onUpdate);
    },
  });

  pi.registerTool({
    ...createBashToolDefinition(localCwd),
    name: "ssh_bash",
    label: "ssh_bash",
    description: `Run a shell command on the remote SSH host. ${localBash.description}`,
    promptSnippet: "Execute bash commands on the remote SSH host (ls, grep, find, etc.)",
    async execute(id, params, signal, onUpdate) {
      const { transport } = requireSsh("ssh_bash");
      const tool = createBashTool(localCwd, { operations: createRemoteBashOps(transport) });
      return tool.execute(id, params, signal, onUpdate);
    },
  });

  pi.on("session_start", async (event, ctx) => {
    const flag = pi.getFlag("ssh") as string | undefined;

    if (flag) {
      // Priority 1: --ssh flag (new connection from user)
      try {
        const rawPort = (pi.getFlag("p") as string | undefined) ?? (pi.getFlag("ssh-port") as string | undefined);
        const port = parseSshPort(rawPort);
        const conn = await resolveSshConnection(flag, localCwd, localHome, port);
        await activateConnection(conn, ctx, { persist: true, verb: "enabled" });
        return;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        await deactivateConnection(ctx);
        console.error(`pi-ssh failed to connect: ${message}`);
        if (ctx.hasUI) ctx.ui.notify(`pi-ssh failed to connect: ${message}`, "error");
        throw error;
      }
    }

    // Priority 2: Stored SSH config from previous session (resume support)
    if (event.reason !== "startup" && event.reason !== "resume") return;

    const entries = ctx.sessionManager.getEntries();
    let storedConfig: SshStoredConfig | undefined;
    for (let i = entries.length - 1; i >= 0; i--) {
      const e = entries[i];
      if (e.type === "custom" && (e as CustomEntry<unknown>).customType === "pi-ssh-config") {
        storedConfig = (e as CustomEntry<SshStoredConfig>).data;
        if (storedConfig) break;
      }
    }

    if (!storedConfig) return;

    try {
      // Persisted config could have been tampered with; re-validate the host
      // before it reaches the ssh argv.
      assertSafeRemote(storedConfig.remote);
      const conn: SshConnection = {
        remote: storedConfig.remote,
        port: storedConfig.port,
        remoteCwd: storedConfig.remoteCwd,
        remoteHome: storedConfig.remoteHome,
        localCwd,
        localHome,
      };
      await activateConnection(conn, ctx, { persist: false, verb: "resumed" });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await deactivateConnection(ctx);
      console.error(`pi-ssh resume failed: ${message}`);
      if (ctx.hasUI) ctx.ui.notify(`pi-ssh resume failed: ${message}`, "warning");
      // Local mode fallback — don't throw, user can still browse the conversation
    }
  });

  // /ssh — connect to (or disconnect from) a remote host mid-session, without
  // requiring --ssh at startup. Mirrors the pi-ssh-tools UX:
  //   /ssh                      pick a host from ~/.ssh/config
  //   /ssh user@host[:/path]    connect (optional trailing port: ... 2222)
  //   /ssh status               show the active connection
  //   /ssh off                  disconnect
  pi.registerCommand("ssh", {
    description: "Connect SSH remote tools: /ssh [user@host[:/path] [port]], /ssh status, /ssh off",
    getArgumentCompletions: (prefix) => {
      const options = ["off", "status", ...readSshConfigHosts()];
      const filtered = options.filter((option) => option.startsWith(prefix));
      return filtered.length > 0 ? filtered.map((option) => ({ value: option, label: option })) : null;
    },
    handler: async (args, ctx) => {
      const input = args.trim();

      if (input === "status") {
        if (!connection) {
          ctx.ui.notify("pi-ssh: not connected (local tools active)", "info");
          return;
        }
        const portLabel = connection.port ?? "ssh-config/default";
        ctx.ui.notify(`pi-ssh: ${connection.remote}:${connection.remoteCwd} (port ${portLabel})`, "info");
        return;
      }

      if (input === "off") {
        if (!connection) {
          ctx.ui.notify("pi-ssh: already off", "info");
          return;
        }
        await deactivateConnection(ctx);
        ctx.ui.notify("pi-ssh: disconnected", "info");
        return;
      }

      let target = input;
      let port: number | undefined;

      if (!target) {
        const hosts = readSshConfigHosts();
        if (hosts.length === 0) {
          ctx.ui.notify("No hosts in ~/.ssh/config. Use /ssh user@host[:/path]", "warning");
          return;
        }
        const items = [...(connection ? ["off"] : []), ...hosts];
        const picked = await ctx.ui.select("SSH target", items);
        if (!picked) return;
        if (picked === "off") {
          await deactivateConnection(ctx);
          ctx.ui.notify("pi-ssh: disconnected", "info");
          return;
        }
        target = picked;
      } else {
        // Allow an optional trailing port: "/ssh user@host[:/path] 2222"
        const parts = target.split(/\s+/);
        if (parts.length > 1 && /^\d+$/.test(parts[parts.length - 1])) {
          port = parseSshPort(parts.pop());
          target = parts.join(" ");
        }
      }

      try {
        const conn = await resolveSshConnection(target, localCwd, localHome, port);
        await activateConnection(conn, ctx, { persist: true, verb: "connected" });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        await deactivateConnection(ctx);
        ctx.ui.notify(`pi-ssh: failed to connect: ${message}`, "error");
      }
    },
  });

  pi.on("session_shutdown", async () => {
    if (transport) {
      await transport.dispose();
      transport = null;
    }
  });

  pi.on("user_bash", () => {
    if (!transport) return;
    return { operations: createRemoteBashOps(transport) };
  });

  pi.on("before_agent_start", async (event) => {
    const conn = getConnection();
    if (!conn) return;

    // The default read/write/edit/bash tools operate on the LOCAL machine.
    // Tell the agent that remote work goes through the ssh_* tools and is
    // rooted at the remote working directory, rather than rewriting the local
    // cwd line (which would wrongly imply the local tools act remotely).
    const portLabel = conn.port ?? "ssh-config/default";
    const guidance =
      `\n\n# Remote SSH workspace\n\n` +
      `An SSH connection to ${conn.remote} (port ${portLabel}) is active. ` +
      `The default read/write/edit/bash tools act on the LOCAL machine. ` +
      `To inspect or change files on the remote host, use the ssh_read, ssh_write, ssh_edit, and ssh_bash tools. ` +
      `(User \`!\` commands run on the remote host.) ` +
      `Remote operations are rooted at the remote working directory ${conn.remoteCwd}; ` +
      `relative paths passed to ssh_* tools resolve against it, and remote absolute paths are used as-is.`;

    let modified = `${event.systemPrompt}${guidance}`;
    if (remoteContextSection) {
      modified += remoteContextSection;
    }
    return {
      systemPrompt: modified,
    };
  });
}
