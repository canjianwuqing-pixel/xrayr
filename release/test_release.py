#!/usr/bin/env python3
"""Exercise the real installer preflight without executing installation commands."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile

from build import PLATFORMS, check_elf

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash") if os.name != "nt" else "C:/Program Files/Git/bin/bash.exe"
INSTALLER = (ROOT / "install.sh").read_text(encoding="utf-8")


def function(name):
    return re.search(r"(?ms)^" + name + r"\(\) \{\n.*?^\}\n", INSTALLER).group()


class ReleaseTest(unittest.TestCase):
    def test_architecture_aliases_and_rejection(self):
        aliases = {"x86_64": "64", "amd64": "64", "x64": "64", "aarch64": "arm64-v8a",
                   "arm64": "arm64-v8a", "armv7l": "armv7", "i386": "386", "i686": "386",
                   "riscv64": "riscv64", "s390x": "s390x"}
        for name, expected in aliases.items():
            with self.subTest(name=name):
                result = subprocess.run([BASH, "-c", function("detect_arch") + '\ndetect_arch "$1"', "test", name], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)
        for name in ("unknown", "armv6l", "ppc64le", ""):
            result = subprocess.run([BASH, "-c", function("detect_arch") + '\ndetect_arch "$1"', "test", name], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")

    def test_elf_architecture_and_static_linking(self):
        for name, item in PLATFORMS.items():
            with self.subTest(name=name):
                cls, enc, machine = item["elf"]
                data = bytearray(128)
                data[:6] = b"\x7fELF" + bytes((cls, enc))
                endian = "<" if enc == 1 else ">"
                struct.pack_into(endian + "H", data, 18, machine)
                self.assertEqual(check_elf(data, name)["machine"], machine)
                for wrong in PLATFORMS.keys() - {name}:
                    with self.assertRaises(ValueError):
                        check_elf(data, wrong)
                struct.pack_into(endian + ("Q" if cls == 2 else "I"), data, 32 if cls == 2 else 28, 64)
                struct.pack_into(endian + "HH", data, 54 if cls == 2 else 42, 32, 1)
                struct.pack_into(endian + "I", data, 64, 3)
                with self.assertRaisesRegex(ValueError, "interpreter"):
                    check_elf(data, name)

    def preflight(self, suffix, failure=None):
        with tempfile.TemporaryDirectory(prefix="kuaiyun-installer-test-") as tmp:
            root = Path(tmp)
            fixture = root / "fixture"
            fixture.mkdir()
            asset = "XrayR-linux-" + suffix + ".zip"
            names = ["XrayR", "config.yml", "dns.json", "route.json", "custom_inbound.json",
                     "custom_outbound.json", "rulelist", "geoip.dat", "geosite.dat"]
            with zipfile.ZipFile(fixture / asset, "w") as z:
                for name in names:
                    if failure == "missing-member" and name == "XrayR":
                        continue
                    z.writestr(name, "controlled-fixture-only")
            if failure == "corrupt-zip":
                (fixture / asset).write_bytes(b"not-a-zip")
            digest = hashlib.sha256((fixture / asset).read_bytes()).hexdigest()
            if failure == "checksum":
                digest = "0" * 64
            (fixture / (asset + ".sha256")).write_text(digest + "  " + asset + "\n", encoding="ascii", newline="\n")
            for name in ("XrayR.sh", "XrayR.service"):
                (fixture / name).write_text("fixture-only", encoding="ascii")
            if failure in ("asset", "checksum-file", "service", "manager"):
                missing = {"asset": asset, "checksum-file": asset + ".sha256", "service": "XrayR.service", "manager": "XrayR.sh"}[failure]
                (fixture / missing).unlink()
            env = os.environ.copy()
            env.update(FIXTURE=fixture.as_posix(), TEST_ARCH=suffix, TEST_LOG=(root / "urls").as_posix(), MUTATED=(root / "mutated").as_posix())
            # Run the actual final gate and prepare_download; replace installation with a counter.
            script = function("prepare_download") + r'''
download_file() {
    printf '%s\n' "$1" >> "$TEST_LOG"
    cp "$FIXTURE/${1##*/}" "$2"
}
install_base() { return 0; }
install_XrayR() { printf 'called' > "$MUTATED"; }
arch="$TEST_ARCH"
''' + INSTALLER[INSTALLER.index('echo -e "${green}开始安装'):]
            result = subprocess.run([BASH, "-c", script, "test", "v0.9.4-ky.3"], env=env, capture_output=True, text=True, encoding="utf-8")
            if failure:
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((root / "mutated").exists(), result.stdout)
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((root / "mutated").read_text(), "called")
                urls = (root / "urls").read_text().splitlines()
                self.assertTrue(urls[0].endswith("/v0.9.4-ky.3/" + asset))
                self.assertEqual(len(urls), 4)
                self.assertTrue(all("/v0.9.4-ky.3/" in url for url in urls))

    def test_each_architecture_asset(self):
        for item in PLATFORMS.values():
            with self.subTest(suffix=item["suffix"]):
                self.preflight(item["suffix"])

    def test_failure_never_enters_installation(self):
        for failure in ("asset", "checksum-file", "checksum", "corrupt-zip", "missing-member", "service", "manager"):
            with self.subTest(failure=failure):
                self.preflight("arm64-v8a", failure)

    def test_real_installer_gate_order(self):
        self.assertLess(INSTALLER.index('arch=$(detect_arch'), INSTALLER.index("install_base()"))
        bottom = INSTALLER[INSTALLER.index('echo -e "${green}开始安装'):]
        self.assertLess(bottom.index('prepare_download "$@"'), bottom.rindex("install_XrayR"))
        self.assertNotIn("/usr/local/XrayR", function("prepare_download"))
        self.assertNotIn("/etc/XrayR", function("prepare_download"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
