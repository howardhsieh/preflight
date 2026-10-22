# Scanning a repository before you open it: how preflight works

*A fake recruiter sends you a take-home assignment. You clone it, open it in VS Code,
click "Yes, I trust the authors", and a backdoor installs itself before you have read a
single line of code. This write-up covers the attack, why the existing advice is "be
careful", and how I built a static scanner that catches the mechanism without ever
executing the repository.*

---

## 1. The attack

Since 2023 a cluster of North Korea-linked campaigns, tracked as **Contagious Interview**
(also "DeceptiveDevelopment", "Void Dokkaebi"), has targeted software developers with
job offers. The lure is mundane: a recruiter, a plausible company, and a coding
assignment delivered as a Git repository. The payload is not in the code you are asked
to write. It is in the plumbing around it.

The variants documented by Microsoft, Trend Micro, GitLab and others share a shape:

1. **A trigger that fires without a conscious decision.** The most effective one is a
   VS Code task with `"runOn": "folderOpen"` in `.vscode/tasks.json`. When you open the
   folder and accept the Workspace Trust prompt (which every developer does, because
   otherwise nothing works), the task runs. Other triggers: `postinstall` in
   `package.json`, `initializeCommand` in `devcontainer.json` (which runs on your *host*,
   not in the container), `setup.py`, `.envrc`, and lately hooks in `.claude/settings.json`.
2. **A payload that does not look like a payload.** A JavaScript file saved as
   `fa-solid-900.woff2` in a fonts directory. A config file whose real content starts at
   column 300, past where any editor shows. `eval(Buffer.from("...", "base64"))`. A fetch
   from `api.npoint.io` or a raw IP followed by `new Function(body)()`.
3. **Stage two**, downloaded by the stager: credential theft (browser profiles, SSH
   keys, cloud credentials, crypto wallets) and a persistent backdoor.

The advice in every vendor write-up is some version of "inspect `tasks.json` before
trusting the workspace" and "open unknown repositories in a VM". That is correct and
nobody does it. I wanted a tool that makes the inspection a single command.

## 2. Design constraints

Three decisions shaped everything else.

**Never execute the target.** This sounds obvious until you notice how many "scanners"
run `npm install` to resolve dependencies or `git status` to list files. A hostile
repository's own `.git/config` can define a `core.fsmonitor` command, so even `git status`
is code execution. preflight walks the filesystem, reads files with size limits, records
symlinks without following them, and parses configuration with its own JSONC parser.
The `clone` subcommand runs `git clone` with `--no-recurse-submodules`,
`core.hooksPath=/dev/null`, `protocol.ext.allow=never`, `protocol.file.allow=never`, and
LFS smudging disabled.

**Zero dependencies.** A tool that checks repositories for supply-chain attacks should
not itself be a supply-chain risk. preflight uses only the Go standard library and ships
as a single static binary with signed provenance.

**Explain the trigger, not just the smell.** Every finding says what *you* would have to
do for the code to run: "opening the folder in VS Code", "installing dependencies",
"starting an AI coding agent". A finding without a trigger is a content smell; a finding
with one is a threat.

## 3. Triggers × content → chains

The core idea is small. Detectors fall into two families:

- **Trigger detectors** parse configuration and record *which files would execute*.
  `tasks.json` → the command's arguments; `package.json` → `postinstall` and, because
  take-home assignments always say "run `npm start`", the `start` and `test` scripts
  too; `devcontainer.json` → lifecycle commands; `.claude/settings.json` → hook commands;
  `.mcp.json` → server commands. Command lines are tokenised, variables such as
  `${workspaceFolder}` and `$CLAUDE_PROJECT_DIR` are stripped, and each token is resolved
  the way Node and shells resolve it (`server` → `server.js` → `server/index.js`).
- **Content detectors** look at files without caring how they are reached: a script
  whose extension claims it is a font (magic bytes), code after 150+ characters of
  whitespace, decode-and-eval on one line, download-and-eval within 1,500 bytes,
  invisible Unicode Tag characters (decoded and shown), Trojan Source bidi controls,
  references to paste sites.

Individually, most of these are weak. 22% of the most popular repositories on GitHub
have an install script. 14% contain `atob` next to `Function(` somewhere, usually in a
bundled module loader. What is rare is the **combination**: a trigger whose resolved
target carries a content signal. That is the `PF001 auto-exec-chain` rule, and it is the
only thing in the scanner I would call a detection rather than a heuristic:

```
[CRITICAL] .vscode/tasks.json:6  PF001 auto-exec-chain
           Opening the folder in VS Code executes public/fonts/fa-solid-900.woff2,
           which contains: disguised-file, decode-and-execute
```

Chains behind automatic triggers are critical. Chains behind a command the user types
(`npm start`) are high, and require a high-severity content finding, because a build
script that runs `tsc` on a file with a long base64 string is not an attack.

## 4. Scoring without the noise

Early versions summed finding weights. A documentation-heavy repository with 300
zero-width spaces scored like one with 300 problems. Two changes fixed that:

- At most **three findings per rule** count towards the score.
- The verdict is `DANGER` on any critical finding, `REVIEW` on any high finding or a score
  of 50 (three different medium rules at the cap), and `CLEAN` otherwise. Low and
  informational findings are shown but never change the verdict.

## 5. The benchmark, and what it taught me

I scanned the **1,000 most-starred repositories on GitHub**, treating them as benign.
The first run reported 73% CLEAN. Five rounds of tuning brought it to **92.9% CLEAN,
6.8% REVIEW, 0.3% DANGER**, without touching the chain rule. The things that were wrong
were more interesting than the things that were right:

1. **Git LFS pointers.** Because the hardened clone disables LFS smudging, every
   LFS-tracked image is a 130-byte text file where a PNG should be. The magic-byte
   check flagged them as "script disguised as an image" in 52 repositories. The
   scanner now recognises the pointer format.
2. **🏴󠁧󠁢󠁥󠁮󠁧󠁿 is made of Unicode Tag characters.** The subdivision flags for England,
   Scotland and Wales are encoded as 🏴 followed by Tag letters and a cancel tag. Any
   emoji dataset lit up as a critical "tag smuggling" finding. Tags that follow U+1F3F4
   are now skipped, and severity depends on what the hidden text decodes to:
   instructions have spaces; `gbenggbsctgbwls` does not.
3. **`RegExp.exec()` is not `exec()`.** My "dynamic execution" regex matched
   `csrfRegex.exec(response)`, `cdp.eval(...)`, `def eval(self)` and `eval()` in a
   comment. It now requires a variable argument, must not be preceded by `.`, and
   skips comment lines.
4. **Minified code looks like malware.** `(globalThis.TURBOPACK||[]).push(...` with
   `atob` and `Function` on a 40 kB line is every Next.js build. Generated code is now
   detected by line density, not just by living under `dist/`.
5. **Popular projects configure their agents.** 3.8% of the top 1,000 ship Claude Code
   hooks and 3.9% ship MCP servers. In a repository you trust they are conveniences.
   In one from a stranger they are the attack surface. These are medium findings now,
   escalated by the chain rule when the script they run is itself suspicious.
6. **Right-to-left languages exist.** Arabic and Urdu translation files use bidi
   control characters legitimately. Trojan Source only matters in source code a human
   reviews, so severity now depends on the path and file type.

The three remaining `DANGER` verdicts are all real instances of the mechanism:
`microsoft/vscode` has a Copilot extension task that genuinely runs on folder open; a
university course archive contains an `.exe` renamed to `.zip`; and
`big-list-of-naughty-strings` really does embed Unicode Tag characters. I consider
those correct.

## 6. What it does not do

preflight finds code that runs *automatically or on the first obvious command*. It is
not a malware scanner, it does not resolve dependencies, and a determined attacker can
evade string heuristics. A `CLEAN` verdict means "no known auto-execution vector", and
the right response to an unknown repository is still a VM or a Codespace in Restricted
Mode. The tool's job is to make sure you know *before* you click "trust".

## 7. Using it

```bash
go install github.com/howardhsieh/preflight/cmd/preflight@latest
preflight clone https://github.com/someone/interview-task   # hardened clone + scan
preflight scan . -f sarif -o preflight.sarif                # for GitHub code scanning
```

Or as a GitHub Action, `howardhsieh/preflight@v0.1.0`, which verifies the release
checksum before running and exposes `verdict` and `score` outputs.

Source, rules and the benchmark are at
[github.com/howardhsieh/preflight](https://github.com/howardhsieh/preflight).

---

*References: Microsoft Threat Intelligence on `tasks.json` abuse (2026); GitLab,
"How to detect and prevent Contagious Interview IDE attacks" (May 2026); Trend Micro on
Void Dokkaebi (April 2026); Cloud Security Alliance research note on Unicode instruction
injection in AI skills (March 2026); Boucher & Anderson, "Trojan Source" (2021).*
