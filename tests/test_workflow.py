"""Regression checks use generated mock tools only, never real forensic tools."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
MOCK = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['CALL_LOG'], 'a') as log:
    log.write(json.dumps([name, args]) + '\n')
if any(flag in args for flag in ('--help', '--version', '-V')):
    print(name + ' mock version 2.0')
    sys.exit(0)
if name == 'trusted vol2':
    step = args[-1]
    print('Plugin header\n-------------')
    if step == 'connscan':
        print('192.0.2.1:443 192.0.2.1:80 999.999.999.999')
        print('https://example.test/path https://999.999.999.999/ https://bad_host.test/')
    else:
        print('one mock record')
else:
    step = name
    if name == 'strings':
        if os.environ.get('MUTATE_EVIDENCE'):
            with open(args[0], 'ab') as image:
                image.write(b' changed by mock')
        print('192.0.2.1 192.0.2.1 999.2.3.4 1.2.3.4.5 https://example.test/path')
    else:
        if name == 'binwalk':
            directory = Path(next(a.split('=', 1)[1] for a in args if a.startswith('--directory=')))
        else:
            directory = Path(args[args.index('-o') + 1])
        (directory / 'nested').mkdir(parents=True)
        (directory / 'report.txt').write_text('metadata')
        (directory / 'nested' / 'carved.bin').write_bytes(b'mock recovered data')
        print('mock extraction completed')
if os.environ.get('FAIL_STEP') == step:
    print('mock tool failure', file=sys.stderr)
    sys.exit(17)
if os.environ.get('SLEEP_STEP') == step:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    child = subprocess.Popen([sys.executable, '-c',
        'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])
    Path(os.environ['CHILD_STATE']).write_text(json.dumps({'parent': os.getpid(), 'child': child.pid, 'group': os.getpgrp()}))
    time.sleep(60)
'''


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix=".mock-test-", dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.bin = self.workspace / "mock tools"
        self.bin.mkdir()
        for name in ("trusted vol2", "binwalk", "bulk_extractor", "foremost", "strings"):
            executable = self.bin / name
            executable.write_text(MOCK)
            executable.chmod(0o700)
        self.input = self.workspace / "evidence with spaces.bin"
        self.input.write_bytes(b"synthetic test fixture only")
        self.output = self.workspace / "results with spaces"
        self.call_log = self.workspace / "calls.jsonl"
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", CALL_LOG=str(self.call_log))

    def run_workflow(self, mode="mem", extra_env=None, extra_args=None):
        args = ["bash", str(ROOT / "anlyz.sh"), mode, str(self.input), "--output", str(self.output)]
        if mode == "mem":
            args += ["--vol", str(self.bin / "trusted vol2"), "--profile", "Win7SP1x64"]
        result = subprocess.run(args + (extra_args or []), env=self.env | (extra_env or {}), cwd=self.workspace,
                                capture_output=True, text=True, timeout=30)
        runs = sorted(self.output.glob("df-*")) if self.output.exists() else []
        return result, runs

    def manifest(self, run):
        return json.loads((run / "manifest.json").read_text())

    def test_memory_once_paths_hashes_and_read_only_plugin_list(self):
        plugin_bytes = (ROOT / "volcom.txt").read_bytes()
        result, runs = self.run_workflow()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(runs), 1)
        data = self.manifest(runs[0])
        self.assertEqual(data["status"], "complete")
        self.assertTrue(data["hash_unchanged"])
        self.assertEqual(data["sha256_before"], hashlib.sha256(self.input.read_bytes()).hexdigest())
        self.assertEqual(data["input"], str(self.input.resolve()))
        calls = [json.loads(line) for line in self.call_log.read_text().splitlines()]
        for plugin in data["plugins"]:
            self.assertEqual(sum(args[-1] == plugin for _, args in calls), 1)
        self.assertEqual(plugin_bytes, (ROOT / "volcom.txt").read_bytes())
        self.assertEqual(data["indicator_summary"]["unique_candidates"], {"IPv4": 1, "URL": 1})
        self.assertIn("not counts of forensic findings", (runs[0] / "summary.md").read_text())
        self.assertEqual(data["tools"]["volatility"]["version_probe_exit_code"], 0)
        self.assertEqual((runs[0] / "manifest.json").stat().st_mode & 0o077, 0)

    def test_failed_plugin_is_preserved_and_other_plugins_run(self):
        result, runs = self.run_workflow(extra_env={"FAIL_STEP": "pslist"})
        self.assertEqual(result.returncode, 1, result.stderr)
        data = self.manifest(runs[0])
        self.assertEqual(data["status"], "failed")
        self.assertEqual(next(step["exit_code"] for step in data["commands"] if step["label"] == "pslist"), 17)
        self.assertIn("mock tool failure", (runs[0] / "logs/pslist.stderr.txt").read_text())
        self.assertTrue((runs[0] / "logs/hivescan.stdout.txt").exists())

    def test_disk_recursive_counts_and_unique_output_directories(self):
        result, runs = self.run_workflow("hdd")
        self.assertEqual(result.returncode, 0, result.stderr)
        first = runs[0]
        original = (first / "manifest.json").read_bytes()
        summary = (first / "summary.md").read_text()
        self.assertIn("| artifacts/binwalk | 2 |", summary)
        self.assertIn("| artifacts/foremost | 2 |", summary)
        data = self.manifest(first)
        self.assertEqual(data["indicator_summary"]["unique_candidates"], {"IPv4": 1, "URL": 1})
        second_result, runs = self.run_workflow("hdd")
        self.assertEqual(second_result.returncode, 0, second_result.stderr)
        self.assertEqual(len(runs), 2)
        self.assertEqual(original, (first / "manifest.json").read_bytes())

    def test_changed_input_hash_fails_run(self):
        result, runs = self.run_workflow("hdd", extra_env={"MUTATE_EVIDENCE": "1"})
        self.assertEqual(result.returncode, 1, result.stderr)
        data = self.manifest(runs[0])
        self.assertFalse(data["hash_unchanged"])
        self.assertEqual(data["status"], "failed")
        self.assertEqual(data["exit_code"], 1)

    def test_missing_vol_or_profile_never_invokes_any_tool(self):
        result = subprocess.run(["bash", str(ROOT / "anlyz.sh"), "mem", str(self.input)],
                                env=self.env, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.call_log.exists())
        result, runs = self.run_workflow(extra_args=["--profile", "bad;profile"])
        self.assertEqual(result.returncode, 2)
        self.assertFalse(runs)
        self.assertFalse(self.call_log.exists())

    def test_invalid_input_and_unknown_mode(self):
        result, runs = self.run_workflow("unknown")
        self.assertEqual(result.returncode, 2)
        self.input.unlink()
        result, runs = self.run_workflow()
        self.assertEqual(result.returncode, 2)
        self.assertFalse(runs)
        self.assertFalse(self.call_log.exists())

    def test_interruption_kills_owned_tool_group_and_preserves_manifest(self):
        state_path = self.workspace / "child-state.json"
        args = ["bash", str(ROOT / "anlyz.sh"), "mem", str(self.input), "--output", str(self.output),
                "--vol", str(self.bin / "trusted vol2"), "--profile", "Win7SP1x64"]
        process = subprocess.Popen(args, env=self.env | {"SLEEP_STEP": "pslist", "CHILD_STATE": str(state_path)},
                                   cwd=self.workspace, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        state = None
        try:
            deadline = time.monotonic() + 5
            while not state_path.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(state_path.exists(), "mock step did not start")
            state = json.loads(state_path.read_text())
            self.assertNotEqual(state["group"], os.getpgrp())
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 143, stdout + stderr)
            data = self.manifest(next(self.output.glob("df-*")))
            self.assertEqual(data["status"], "interrupted")
            self.assertTrue(data["hash_unchanged"])
            for pid in (state["parent"], state["child"]):
                stat_path = Path(f"/proc/{pid}/stat")
                if stat_path.exists():
                    self.assertEqual(stat_path.read_text().split(")", 1)[1].split()[0], "Z")
        finally:
            if state and state["group"] != os.getpgrp():
                try:
                    os.killpg(state["group"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
