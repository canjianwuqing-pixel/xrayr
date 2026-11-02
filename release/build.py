#!/usr/bin/env python3
"""Build the original installer layout from an exact, clean Git commit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CORE = "v1.260327.1-0.20260728075948-5ca6f4b7d4dc"
CORE_COMMIT = "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
ASSET = "XrayR-linux-64.zip"
FILES = {
    "config.yml": "release/config/config.yml.example",
    "dns.json": "release/config/dns.json",
    "route.json": "release/config/route.json",
    "custom_outbound.json": "release/config/custom_outbound.json",
    "custom_inbound.json": "release/config/custom_inbound.json",
    "rulelist": "release/config/rulelist",
    "geoip.dat": "release/config/geoip.dat",
    "geosite.dat": "release/config/geosite.dat",
    "README.md": "README.md",
    "LICENSE": "LICENSE",
    "LICENSE.xray-core": "common/corecompat/LICENSE.xray-core",
    "PROVENANCE.txt": "common/corecompat/PROVENANCE.txt",
}


def run(*args, env=None):
    return subprocess.check_output(args, cwd=ROOT, env=env)


def source(path):
    # Use canonical committed bytes on Windows and Linux, including geo assets.
    return run("git", "show", "HEAD:" + path)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "out" / "release")
    output = parser.parse_args().output.resolve()
    if run("git", "status", "--porcelain=v1", "--untracked-files=all").strip():
        raise SystemExit("Refusing release build from an uncommitted worktree")
    commit = run("git", "rev-parse", "HEAD").decode().strip()
    if os.environ.get("GITHUB_SHA", commit) != commit:
        raise SystemExit("Checkout does not match the workflow commit")
    env = os.environ.copy()
    env.update(GOTOOLCHAIN="local", CGO_ENABLED="0", GOOS="linux", GOARCH="amd64", GOAMD64="v1")
    version = run("go", "version", env=env).decode().strip()
    if not re.search(r"\bgo1\.26\.5\b", version):
        raise SystemExit("This release requires exactly Go 1.26.5: " + version)
    module = json.loads(run("go", "list", "-mod=readonly", "-m", "-json", "github.com/xtls/xray-core", env=env))
    if module["Version"] != CORE or module.get("Replace"):
        raise SystemExit("Unexpected Xray-core module or replacement")
    if not re.search(rb'version\s*=\s*"0\.9\.4"', source("cmd/version.go")):
        raise SystemExit("XrayR program version must remain 0.9.4")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kuaiyun-build-") as tmp:
        binary = Path(tmp) / "XrayR"
        subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-ldflags=-s -w -buildid=", "-o", str(binary), "."], cwd=ROOT, env=env, check=True)
        build_info = run("go", "version", "-m", str(binary), env=env).decode()
        if "\tdep\tgithub.com/xtls/xray-core\t" + CORE + "\t" not in build_info:
            raise SystemExit("Compiled binary does not contain the pinned Xray-core")
        for setting in ["CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "vcs.revision=" + commit, "vcs.modified=false"]:
            if setting not in build_info:
                raise SystemExit("Binary build setting missing: " + setting)
        payload = {"XrayR": binary.read_bytes()}
    payload.update({name: source(path) for name, path in FILES.items()})
    if payload["XrayR"][:5] != b"\x7fELF\x02" or int.from_bytes(payload["XrayR"][18:20], "little") != 62:
        raise SystemExit("Not an ELF64 x86-64 executable")
    info = {
        "release_tag_proposal": "v0.9.4-ky.1", "xrayr_version": "0.9.4",
        "xray_core_version": "26.7.28", "xray_core_module": CORE,
        "xray_core_commit": CORE_COMMIT, "source_commit": commit,
        "go_version": "1.26.5", "goos": "linux", "goarch": "amd64", "cgo_enabled": 0,
        "asset_name": ASSET, "file_sha256": {name: digest(data) for name, data in payload.items()},
    }
    payload["BUILD-INFO.json"] = (json.dumps(info, ensure_ascii=False, indent=2) + "\n").encode()
    archive = output / ASSET
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, data in sorted(payload.items()):
            entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (0o100755 if name == "XrayR" else 0o100644) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(entry, data, compresslevel=9)
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None or set(z.namelist()) != set(payload):
            raise SystemExit("ZIP integrity/layout failure")
    sha = digest(archive.read_bytes())
    (output / (ASSET + ".sha256")).write_text(sha + "  " + ASSET + "\n", encoding="ascii", newline="\n")
    (output / "BUILD-INFO.json").write_bytes(payload["BUILD-INFO.json"])
    (output / "binary-build-info.txt").write_text(build_info, encoding="utf-8", newline="\n")
    print(json.dumps({"source_commit": commit, "zip": str(archive), "sha256": sha, "size": archive.stat().st_size}, ensure_ascii=False))


if __name__ == "__main__":
    main()
