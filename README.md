# DF-Automation

A Bash digital-forensics learning project intended to automate disk-image carving and memory-image analysis.

## Current status: execution blocked

**The current `anlyz.sh` fails Bash syntax validation.** An unmatched closing `)` in the HDD function's IP/URL extraction command prevents the script from running, including its memory-analysis mode.

This README documents the existing code and its intended workflow. The syntax error and other script issues have not been fixed. No evidence files or bundled executables were run during this documentation review.

## Repository contents

| File | Purpose |
| --- | --- |
| [anlyz.sh](anlyz.sh) | Main Bash wrapper with `hdd` and `mem` modes. |
| [volcom.txt](volcom.txt) | Memory-plugin names; overwritten by the memory workflow. |
| `vol` | Bundled executable invoked as `./vol`. Its version, provenance, and host compatibility are not established by the repository documentation. |

The wrapper uses Volatility 2-style commands such as `imageinfo` and `--profile`. It is not a Volatility 3 wrapper.

## Intended workflows

### Disk / file analysis

The `HDD` function attempts to:

- Run Binwalk extraction, Bulk Extractor, and Foremost against the input.
- Extract printable strings.
- Collect the outputs under an input-derived `.ext` directory.
- Print basic file/line counts and extract possible IP addresses and URLs.

### Memory analysis

The `MEM` function attempts to:

- Run `./vol -f <image> imageinfo`.
- Select a profile by parsing that command's text output.
- Run `pslist`, `pstree`, `psscan`, `dlllist`, `privs`, `modules`, `driverscan`, `connscan`, and `hivescan`.
- Write combined plugin output and a line-count summary.

Plugin availability depends on the memory image and the compatible analysis tool/profile.

## Dependencies referenced by the code

- Linux with Bash.
- Binwalk, Bulk Extractor, Foremost, and `strings` for disk/file analysis.
- A compatible `./vol` executable and `figlet` for memory analysis.
- Standard utilities including `grep`, `awk`, `sed`, `wc`, `tee`, and filesystem commands.
- Read access to a working copy of the evidence and sufficient output storage.

There is no dependency installer or pinned tool-version manifest.

## Intended command interface

These commands describe the parser in the source; **they will not run successfully until the syntax error is corrected**:

```text
bash anlyz.sh hdd <image-file>
bash anlyz.sh mem <memory-image>
```

The memory workflow resolves `./vol` relative to the current working directory. There is no built-in help, output-directory option, or input validation.

Use working copies of evidence. The script does not implement evidence hashing, provenance tracking, or chain-of-custody records.

## Expected output after execution is repaired

| Mode | Paths used by the source |
| --- | --- |
| HDD | Input-derived `.bw`, `.be`, `.fm`, and `.str` outputs, moved into an input-derived `.ext` directory; `ext.sum` in the working directory. |
| MEM | `mem.ext`, `mem.sum`, and a regenerated `volcom.txt` in the working directory. |

The final memory messages incorrectly refer to `mem.info` and `mem.analyzer`; those are not the report filenames written by the code. For HDD mode, only the initial report heading is piped into `ext.sum`, so the full summary is not saved.

## Known limitations

- The blocking syntax error affects both modes.
- Arguments and paths are unquoted; spaces and input paths containing directories can break commands and report paths.
- Tool failures are largely hidden by stderr redirection, and exit codes are not checked.
- The final `exit 0` would report success even after many processing failures once the syntax issue is fixed.
- Profile selection relies on a fixed text field and does not validate the result.
- Memory plugins are run again to count lines, repeating expensive analysis.
- Line counts and the HDD file counts are not reliable measures of forensic findings.
- The IP/URL pattern is overly broad and does not validate extracted indicators.
- Fixed output filenames can overwrite earlier results.
- There are no input hashes, per-tool execution records, or consistent error logs.

## Potential improvements

- Fix syntax and add mode, file, dependency, and permission checks.
- Separate input paths from output names and create a unique case directory.
- Preserve tool stdout, stderr, exit codes, timestamps, and versions.
- Hash the input before and after analysis and include hashes in a run manifest.
- Run each memory plugin once and summarize its saved output.
- Replace fragile profile parsing with explicit selection or a separately scoped migration to Volatility 3.
- Correct report filenames and counts, and validate extracted indicators.
- Document and verify the analysis-tool distribution instead of relying on an unexplained binary.

These are proposed changes; only documentation has been added.
