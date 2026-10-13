# DF-Automation

A Bash digital-forensics learning project for disk/file carving and Volatility 2 memory analysis. The wrapper keeps each run's tool output, errors, command records, and input hashes together.

**Status: functional wrapper with mock-tested workflows; validation against real forensic tools and representative evidence remains outstanding.** This is a learning/analyst-assistance project, not a validated forensic acquisition or chain-of-custody system.

## What changed

- Fixed the Bash syntax error that prevented both modes from running.
- Added input/dependency checks, help, quoted absolute paths, and a unique output directory for every run.
- Preserved stdout, stderr, exit codes, UTC timestamps, exact argument arrays, and tool version-probe output.
- Added SHA-256 hashing before and after analysis; a mismatch or unreadable input at completion fails the run.
- Run each configured memory plugin once and summarize its saved output. `volcom.txt` is read without modification.
- Require an explicit trusted Volatility executable and an analyst-selected profile.
- Added recursive extraction-file totals and validated, deduplicated IPv4/HTTP(S) URL candidates with clear counting limitations.

## Requirements

- Linux, Bash 4 or later, Python 3.9 or later (standard library only), GNU coreutils including `timeout` and `mktemp`, and util-linux `setsid`.
- Disk mode: Binwalk with the legacy `-eq --directory` command interface, Bulk Extractor, Foremost, and GNU `strings` on `PATH`.
- Memory mode: a separately configured, trusted **Volatility 2-compatible executable** and a compatible memory profile. An executable launcher may be used if your installation requires its own Python runtime.
- A readable regular input file and sufficient space in the output directory.

There is no automatic package installation. Tool versions are recorded, not pinned. A failed or unsupported version probe is logged without failing the analysis itself. Each version probe has a 15-second timeout; analysis steps have no artificial time limit.

## Usage

```bash
bash anlyz.sh --help

bash anlyz.sh hdd "/cases/case 01/disk image.dd" \
  --output "/cases/case 01/analysis"

bash anlyz.sh mem "/cases/case 02/memory image.raw" \
  --vol "/opt/trusted-volatility2/vol" \
  --profile Win7SP1x64 \
  --output "/cases/case 02/analysis"
```

The default output root is `./df-results`, relative to your working directory. Relative paths, full paths, and paths containing spaces are supported. Each invocation creates a separate `df-<mode>-<UTC time>-<random suffix>` directory; previous results are retained. New output uses `umask 077` to restrict access to its owner unless an external tool explicitly changes permissions.

Memory mode runs `imageinfo` for reference and then the plugins in `volcom.txt`: `pslist`, `pstree`, `psscan`, `dlllist`, `privs`, `modules`, `driverscan`, `connscan`, and `hivescan`. `imageinfo` does **not** silently select or override `--profile`. Select and verify a profile yourself; unsupported plugins or an incompatible profile may fail, and a zero exit alone does not prove the profile was correct. Blank lines and lines beginning with `#` are ignored in the plugin list; duplicate or invalid names are rejected before execution.

### Volatility executable provenance

The repository contains a legacy `vol` binary whose version, origin, and compatibility have not been established. **The wrapper never selects or executes it automatically.** Supply `--vol` with the path to an executable you have independently obtained and verified. This update does not download, replace, or validate the bundled binary and does not migrate the project to Volatility 3.

Disk mode invokes the external extraction tools against a working copy of the input. Their extraction behavior, external helper programs, and supported file formats depend on their installed versions. The wrapper does not sandbox those tools or make the input read-only; before/after hashes detect a net content change but cannot prevent one or detect temporary changes restored before the final hash.

## Output

| Path inside the run directory | Content |
| --- | --- |
| `manifest.json` | Input path, mode/profile/plugins, before/after hashes, final status, command argument arrays, timestamps, exit codes, and version-probe records. |
| `summary.md` | Run status, hashes, step outcomes, saved-output links, and qualified counts. |
| `logs/<step>.stdout.txt` | Complete stdout for a version probe, extraction tool, or memory plugin. `strings.stdout.txt` contains the printable strings. |
| `logs/<step>.stderr.txt` | Complete stderr, retained even when a tool fails. |
| `artifacts/binwalk/`, `artifacts/bulk_extractor/`, `artifacts/foremost/` | Disk extraction output, when the respective tool creates it. |
| `indicators.tsv` | Deduplicated candidate IPv4 addresses and HTTP(S) URLs from disk strings or memory `connscan` output. Created when the relevant saved output exists. |

Extraction totals count regular files recursively, excluding symlinks, and can include reports/metadata. Memory output-line totals include headers; they are **not** counts of processes or forensic findings. Indicator candidates are validated syntactically without network lookups. They can come from incomplete tool output and do not establish maliciousness or attribution. IPv6 candidate extraction and cross-tool evidence correlation are not implemented.

Failed analysis steps are recorded, subsequent independent steps are still attempted, and the run returns nonzero. Each tool runs in a separate process group. Ctrl+C or SIGTERM triggers TERM to the current tool's group, then KILL after a grace period of up to two seconds, followed by reaping and final records/hashes. Descendants that deliberately detach into another session are outside that group. Forced termination, power loss, or output-disk failure can leave incomplete reports.

| Exit code | Meaning |
| --- | --- |
| `0` | All requested analysis steps completed with zero exit and the final hash matched. |
| `1` | Analysis/reporting failure or input-hash mismatch. |
| `2` | Invalid input, missing dependencies, or setup failure. |
| `130` / `143` | Interrupted / terminated. |

## Repository files

| File | Purpose |
| --- | --- |
| `anlyz.sh` | Bash argument validation and tool orchestration. |
| `report.py` | Standard-library hashing, manifests, summaries, and indicator validation. |
| `volcom.txt` | Editable memory-plugin list; never regenerated by the wrapper. |
| `vol` | Unverified legacy executable; no automatic invocation. |
| `tests/test_workflow.py` | Isolated regression checks using synthetic fixtures and generated mock tools. |

## Local checks

```bash
bash -n anlyz.sh
python3 -m unittest discover -s tests -v
```

Tests exercise paths with spaces, one invocation per memory plugin, unchanged plugin configuration, recursive file totals, unique run directories, private output permissions, preserved failures, candidate validation, hash-change detection, and bounded interruption of a TERM-ignoring mock tool and child. They do not execute the bundled binary, real forensic tools, or real evidence, and do not make network requests.
