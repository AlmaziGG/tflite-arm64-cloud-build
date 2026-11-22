#!/usr/bin/env python3
"""CI-only verification of a specific published diagnostics ZIP on a fresh runner."""

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

NAME = "bazel-jsonproto-structure-report"
STRUCTURE = f"{NAME}.txt"
TOOLCHAINS = ("toolchain-library-sanitized.txt", "toolchain-smoke-sanitized.txt")
REPORTS = (STRUCTURE, *TOOLCHAINS)
MEMBERS = {*REPORTS, "SHA256SUMS"}
MAX_BYTES = 8 * 1024 * 1024  # Text-only artifact.
FORBIDDEN = re.compile(
    r"ACTION_SECRET|Bearer |gh[pousr]_|github_pat_|raw_command=|action_dump=|response_file_contents="
    r"|execve\(|(?:^|[\s=])/(?!/)|/home/runner/|/tmp/|[A-Za-z]:\\|work/private-diagnostics"
    r'|"actions"\s*:|^SUBCOMMAND:|^ *\$ |BEGIN [A-Z ]*PRIVATE KEY', re.I | re.M
)


def check_sanitized(path):
    content = path.read_text(encoding="utf-8")
    if not content or FORBIDDEN.search(content):
        raise ValueError("empty or unsafe sanitized report")


def check_production(path):
    content = path.read_text(encoding="utf-8")
    if re.findall(r"^collector_exit_code=(.*)$", content, re.M) != ["0"]:
        raise ValueError("collector did not report exit 0")
    blocks = re.split(r"^ACTION (CppCompile|CppLink) #\d+$", content, flags=re.M)
    if set(blocks[1::2]) != {"CppCompile", "CppLink"}:
        raise ValueError("missing compile or link diagnostic evidence")
    for kind, block in zip(blocks[1::2], blocks[2::2]):
        fields = {"compiler_resolution_status": "RESOLVED", "effective_sysroot_status": "RESOLVED"}
        if kind == "CppLink":
            fields.update(actual_linker_identity_status="RESOLVED", linker_resolution_status="RESOLVED",
                          linker_trace_action_exit="0")
        for field, expected in fields.items():
            values = re.findall(rf"^{field}=([^:\n]+)(?::.*)?$", block, re.M)
            if values != [expected]:
                raise ValueError(f"{path.name}: missing or unresolved {kind} {field}")


def verify_zip(data, digest, directory):
    if digest != "sha256:" + hashlib.sha256(data).hexdigest():
        raise ValueError("published ZIP digest mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) != len(MEMBERS) or {item.orig_filename for item in entries} != MEMBERS:
            raise ValueError("ZIP does not match exact four-file allowlist")
        for item in entries:
            if not 0 < item.file_size <= MAX_BYTES or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG):
                raise ValueError("empty, oversized or non-regular ZIP member")
            (directory / item.filename).write_bytes(archive.read(item))
    manifest = (directory / "SHA256SUMS").read_bytes()
    rows = re.findall(rb"^[0-9a-f]{64}  ([a-z0-9.-]+)\n", manifest, re.M)
    if (not re.fullmatch(rb"(?:[0-9a-f]{64}  [a-z0-9.-]+\n){3}", manifest)
            or sorted(name.decode("ascii") for name in rows) != sorted(REPORTS)):
        raise ValueError("invalid three-file manifest")
    subprocess.run(["sha256sum", "--check", "--strict", "SHA256SUMS"], cwd=directory, check=True)
    for name in TOOLCHAINS:
        check_sanitized(directory / name)
    inspector = Path(__file__).with_name("inspect-bazel-jsonproto.py")
    subprocess.run([sys.executable, str(inspector), "--validate-report", str(directory / STRUCTURE)], check=True)


class TemporarilyUnavailable(Exception):
    pass


def request(url):
    # Authorize the GitHub endpoint only. curl strips Authorization on a
    # cross-host redirect to signed storage. Never print URLs, headers or bodies.
    with tempfile.NamedTemporaryFile() as body:
        result = subprocess.run(
            ["curl", "--disable", "--silent", "--location", "--proto", "=https", "--proto-redir", "=https",
             "--max-redirs", "3", "--max-time", "60", "--max-filesize", str(MAX_BYTES),
             "--header", "@-", "--output", body.name, "--write-out", "%{http_code}", url],
            input=f"Authorization: Bearer {os.environ['GITHUB_TOKEN']}\n".encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        status = int(result.stdout or b"0")
        if status in (401, 403):
            raise ValueError(f"artifact access denied (HTTP {status})")
        if result.returncode in (6, 7, 18, 28, 52, 56) or status in (404, 408, 429, 500, 502, 503, 504):
            raise TemporarilyUnavailable(f"HTTP {status}, curl {result.returncode}")
        if result.returncode or status != 200:
            raise ValueError(f"artifact request failed (HTTP {status}, curl {result.returncode})")
        body.seek(0)
        return body.read()


def download(env, get=request, sleep=time.sleep):
    artifact_id = env["ARTIFACT_ID"]
    if not re.fullmatch(r"[1-9][0-9]*", artifact_id):
        raise ValueError("missing or invalid upload artifact ID")
    url = f"https://api.github.com/repos/{env['GITHUB_REPOSITORY']}/actions/artifacts/{artifact_id}"
    for attempt in range(1, 6):
        try:
            metadata = json.loads(get(url))
            run = metadata["workflow_run"]
            if (metadata["id"] != int(artifact_id) or metadata["name"] != NAME or metadata["expired"]
                    or run["id"] != int(env["GITHUB_RUN_ID"]) or run["head_sha"] != env["GITHUB_SHA"]
                    or run["repository_id"] != int(env["REPOSITORY_ID"])
                    or run["head_repository_id"] != int(env["REPOSITORY_ID"])):
                raise ValueError("published artifact identity does not match this run")
            return get(url + "/zip"), metadata["digest"]
        except TemporarilyUnavailable as exc:
            print(f"Artifact temporarily unavailable, attempt {attempt}/5 ({exc})", flush=True)
            if attempt == 5:
                raise ValueError("artifact unavailable after five attempts") from None
            sleep(5 * attempt)


def main():
    if sys.argv[1:] == ["production-gate"]:
        for name in TOOLCHAINS:
            check_production(Path("artifacts") / name)
        return
    if sys.argv[1:] == ["check-sanitized"]:
        for name in TOOLCHAINS:
            check_sanitized(Path("artifacts") / name)
        return
    if sys.argv[1:]:
        raise ValueError("unknown verification mode")
    data, digest = download(os.environ)
    with tempfile.TemporaryDirectory() as directory:
        verify_zip(data, digest, Path(directory))
    summary = (f"Verified artifact {os.environ['ARTIFACT_ID']} for run {os.environ['GITHUB_RUN_ID']}. "
               f"ZIP {digest}. Exact four-file allowlist, three SHA-256 checks and public report safety passed.")
    print(summary)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
        print(summary, file=output)


if __name__ == "__main__":
    main()
