#!/usr/bin/env python3
"""Local reporting helper for anlyz.sh; never executes analysis tools."""
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def save(root, data):
    temporary = root / "manifest.json.tmp"
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temporary.replace(root / "manifest.json")


IPV4 = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
URL = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE)


def valid_url(candidate):
    candidate = candidate.rstrip(".,;!")
    for left, right in (("(", ")"), ("[", "]"), ("{", "}")):
        while candidate.endswith(right) and candidate.count(right) > candidate.count(left):
            candidate = candidate[:-1]
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        _ = parsed.port  # Validate numeric ports and their range.
        if not host or "\\" in parsed.netloc:
            return None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if re.fullmatch(r"[0-9.]+", host):
                return None
            ascii_host = host.rstrip(".").encode("idna").decode("ascii")
            if len(ascii_host) > 253 or not all(HOST_LABEL.fullmatch(p) for p in ascii_host.split(".")):
                return None
        return candidate
    except (ValueError, UnicodeError):
        return None


def indicators(path):
    found = set()
    lines = words = 0
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            lines += 1
            words += len(line.split())
            for match in IPV4.finditer(line):
                try:
                    found.add(("IPv4", str(ipaddress.IPv4Address(match.group()))))
                except ValueError:
                    pass
            for match in URL.finditer(line):
                url = valid_url(match.group())
                if url:
                    found.add(("URL", url))
    return sorted(found), lines, words


def file_count(directory):
    count = 0
    for parent, _, files in os.walk(directory, followlinks=False):
        for name in files:
            path = Path(parent) / name
            if path.is_file() and not path.is_symlink():
                count += 1
    return count


def summary(root, data):
    text = ["# DF-Automation run", "", f"Status: **{data['status']}**", "",
            f"Input: `{data['input']}`", f"Mode: `{data['mode']}`",
            f"Started (UTC): {data['started_at']}", f"Finished (UTC): {data['finished_at']}", "",
            f"SHA-256 before: `{data['sha256_before']}`",
            f"SHA-256 after: `{data.get('sha256_after')}`",
            f"Hash unchanged: **{data['hash_unchanged']}**", ""]
    if data.get("hash_error"):
        text += [f"Hash error: {data['hash_error']}", ""]
    if data["mode"] == "mem":
        text += [f"Explicit Volatility 2 profile: `{data['profile']}`", ""]
    text += ["## Analysis steps", "", "| Step | Exit code | Output lines | Saved output |",
             "| --- | --- | --- | --- |"]
    for step in data["commands"]:
        if step["label"].startswith("version_"):
            continue
        stdout = root / step["stdout"]
        with stdout.open("rb") as stream:
            count = sum(1 for _ in stream)
        text.append(f"| {step['label']} | {step['exit_code']} | {count} | [{step['stdout']}]({step['stdout']}) |")
    text += ["", "Output line counts include headers and are not counts of forensic findings.",
             "Nonzero exits can leave partial outputs. Stderr and exact argument arrays are preserved in manifest.json.", ""]
    if data["mode"] == "hdd":
        text += ["## Extraction output", "", "| Directory | Regular files (recursive) |", "| --- | --- |"]
        for name in ("binwalk", "bulk_extractor", "foremost"):
            directory = root / "artifacts" / name
            count = str(file_count(directory)) if directory.is_dir() else "Not created"
            text.append(f"| artifacts/{name} | {count} |")
        text += ["", "These totals include tool reports and metadata; they are not counts of recovered evidence items.", ""]
    source = root / "logs" / ("strings.stdout.txt" if data["mode"] == "hdd" else "connscan.stdout.txt")
    if source.exists():
        found, lines, words = indicators(source)
        with (root / "indicators.tsv").open("w", encoding="utf-8") as stream:
            stream.write("type\tvalue\tsource\n")
            for kind, value in found:
                stream.write(f"{kind}\t{value}\t{source.relative_to(root)}\n")
        counts = {kind: sum(k == kind for k, _ in found) for kind in ("IPv4", "URL")}
        data["indicator_summary"] = {"source": str(source.relative_to(root)), "unique_candidates": counts,
                                     "source_lines": lines, "source_words": words}
        text += ["## Indicator candidates", "", f"Source: `{source.relative_to(root)}`",
                 f"Unique syntactically valid IPv4 candidates: {counts['IPv4']}",
                 f"Unique syntactically valid HTTP(S) URL candidates: {counts['URL']}",
                 "", "See [indicators.tsv](indicators.tsv). Candidates are deduplicated, may originate from partial output,",
                 "and require analyst review. Syntax validation does not establish reachability, attribution, or maliciousness.",
                 "No DNS lookups or network checks are performed."]
    (root / "summary.md").write_text("\n".join(text) + "\n", encoding="utf-8")


def main(argv):
    action, *args = argv
    if action == "absolute":
        print(Path(args[0]).resolve())
        return 0
    root = Path(args[0])
    if action == "init":
        _, input_path, mode, profile, *plugins = args
        save(root, {"schema_version": 1, "input": input_path, "mode": mode, "profile": profile or None,
                    "plugins": plugins, "started_at": now(), "status": "running", "sha256_before": sha256(input_path),
                    "commands": [], "tools": {}, "reporting_python_version": sys.version})
        return 0
    data = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if action == "step":
        _, label, started, ended, code, *command = args
        data["commands"].append({"label": label, "argv": command, "started_at": started, "finished_at": ended,
                                 "exit_code": int(code), "stdout": f"logs/{label}.stdout.txt",
                                 "stderr": f"logs/{label}.stderr.txt"})
    elif action == "tool":
        _, name, executable = args
        step = next(s for s in reversed(data["commands"]) if s["label"] == f"version_{name}")
        reported = []
        for field in ("stderr", "stdout"):
            with (root / step[field]).open(encoding="utf-8", errors="replace") as stream:
                for _, line in zip(range(12), stream):
                    reported.append(line.rstrip())
        data["tools"][name] = {"executable": executable, "version_probe": step["label"],
                                "version_probe_exit_code": step["exit_code"], "reported_version_output": reported}
    elif action == "finish":
        status = int(args[1])
        data["finished_at"] = now()
        try:
            data["sha256_after"] = sha256(data["input"])
            data["hash_unchanged"] = data["sha256_before"] == data["sha256_after"]
        except OSError as error:
            data["sha256_after"] = None
            data["hash_unchanged"] = False
            data["hash_error"] = str(error)
        if not data["hash_unchanged"] and status == 0:
            status = 1
        data["exit_code"] = status
        data["status"] = "complete" if status == 0 else "interrupted" if status in (130, 143) else "failed"
        summary(root, data)
        save(root, data)
        return 0 if status == 0 else 1
    else:
        raise ValueError(f"Unknown action: {action}")
    save(root, data)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, IndexError) as error:
        print(f"Reporting error: {error}", file=sys.stderr)
        sys.exit(1)
