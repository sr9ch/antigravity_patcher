#!/usr/bin/env python3
"""Юнит-тесты для agy_region_fix (без записи в реальный бинарник)."""

import os
import shutil
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agy_region_fix as fix  # noqa: E402


CLI_SIG = (
    b"\x48\x85\xc9\x0f\x84\x11\x22\x33\x44"
    b"\x80\x79\x08\x00\x0f\x85\x55\x66\x77\x88"
    b"\x48\x89\xc8\x90\xe8\x99\xaa\xbb\xcc"
    b"\x48\x89\x84\x24\xe0\x00\x00\x00"
    b"\x48\x89\x9c\x24\xe8\x00\x00\x00"
    b"\x48\x89\x8c\x24\xf0\x00\x00\x00"
)

HUB_SIG = (
    b"\x80\x78\x08\x00\x74\x0a"
    b"\x48\x8b\x54\x24\x70\x48\x89\x50\x60"
)


def gate_states(data: bytes):
    return fix.scan_gates(data, ((0, len(data)),), fix.GATES)


class GateScanTests(unittest.TestCase):
    def test_original_both_found(self):
        data = b"\x00" * 32 + CLI_SIG + b"\x00" * 32 + HUB_SIG + b"\x00" * 32
        states = {s.gate.key: s for s in gate_states(data)}
        self.assertEqual(states["cli"].state, "original")
        self.assertEqual(states["hub"].state, "original")
        self.assertEqual(states["cli"].offset, 32)
        self.assertEqual(states["hub"].offset, 32 + len(CLI_SIG) + 32)

    def test_apply_makes_patched_and_idempotent(self):
        data = bytearray(b"\x00" * 8 + CLI_SIG + b"\x00" * 8 + HUB_SIG + b"\x00" * 8)
        states = gate_states(bytes(data))
        changed = fix.apply_gates(data, states)
        self.assertEqual({s.gate.key for s in changed}, {"cli", "hub"})

        after = {s.gate.key: s for s in gate_states(bytes(data))}
        self.assertEqual(after["cli"].state, "patched")
        self.assertEqual(after["hub"].state, "patched")

        # повторное применение ничего не меняет
        self.assertEqual(fix.apply_gates(data, gate_states(bytes(data))), [])

    def test_ambiguous_signature_rejected(self):
        data = b"\x00" * 4 + CLI_SIG + b"\x00" * 4 + CLI_SIG
        states = {s.gate.key: s for s in gate_states(data)}
        self.assertEqual(states["cli"].state, "ambiguous")

    def test_mixed_signature_rejected(self):
        patched_cli = CLI_SIG.replace(b"\x80\x79\x08\x00", b"\x48\x85\xc9\x90")
        data = CLI_SIG + patched_cli
        states = {s.gate.key: s for s in gate_states(data)}
        self.assertEqual(states["cli"].state, "mixed")

    def test_patched_bytes_are_expected(self):
        data = bytearray(b"\x00" * 8 + CLI_SIG)
        fix.apply_gates(data, gate_states(bytes(data)))
        at = 8 + 9
        self.assertEqual(bytes(data[at:at + 4]), b"\x48\x85\xc9\x90")

    def test_unknown_binary_has_no_gates(self):
        states = gate_states(b"\x90" * 4096)
        self.assertTrue(all(s.state == "absent" for s in states))

    def test_elf_parser_rejects_non_elf(self):
        with self.assertRaises(fix.UnsupportedBinary):
            fix.parse_elf(b"not an elf" + b"\x00" * 100)

    def test_parser_on_real_binary_if_present(self):
        """Разбор настоящего agy, если он есть в системе (иначе тест пропускается)."""
        candidates = [shutil.which("agy.exe"), shutil.which("agy"),
                      str(Path.home() / ".local/bin/agy"),
                      str(Path.home() / ".gemini/bin/agy")]
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            candidates.append(str(Path(local_app_data) / "agy" / "bin" / "agy.exe"))
        existing = [Path(p) for p in candidates if p and Path(p).is_file()]
        if not existing:
            self.skipTest("agy не установлен")
        info = fix.parse_binary(existing[0].read_bytes())
        self.assertIn(info.kind, ("pe", "elf", "macho"))
        self.assertTrue(info.arch)
        self.assertTrue(all(s.ranges for s in info.slices))


class SafetyTests(unittest.TestCase):
    def test_hash_detects_change(self):
        a = b"a" * 100
        b = b"a" * 99 + b"b"
        self.assertNotEqual(fix.sha256_bytes(a), fix.sha256_bytes(b))

    def test_state_dir_is_writable(self):
        d = fix.state_dir()
        self.assertTrue(d.is_dir())
        self.assertTrue(os.access(d, os.W_OK))


# --------------------------------------------------------------------------
# Mach-O (macOS) — синтетические бинарники, без реального Mac
# --------------------------------------------------------------------------

CPU_X64 = 0x01000007
CPU_ARM64 = 0x0100000C
SIG_OFF = 104  # 32 (header) + 72 (LC_SEGMENT_64)


def macho_thin(cputype: int, payload: bytes) -> bytes:
    size = SIG_OFF + len(payload)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, cputype, 3, 2, 1, 72, 0, 0)
    seg = struct.pack(
        "<II16sQQQQiiII",
        0x19, 72, b"__TEXT".ljust(16, b"\x00"),
        0x100000000, size, 0, size, 5, 5, 0, 0,
    )
    return header + seg + payload


def macho_fat(entries) -> bytes:
    n = len(entries)
    base = 8 + 20 * n
    chunks, metas, cur = [], [], base
    for cpu, blob in entries:
        pad = (-cur) % 0x1000
        chunks.append(b"\x00" * pad + blob)
        cur += pad
        metas.append((cpu, cur, len(blob)))
        cur += len(blob)
    out = bytearray(struct.pack(">II", 0xCAFEBABE, n))
    for cpu, off, size in metas:
        out += struct.pack(">IIIII", cpu, 3, off, size, 12)
    out += b"".join(chunks)
    return bytes(out)


ARM_CLI_ORIG = (
    b"\x02\x20\x40\x39" b"\x02\x00\x02\x37" b"\x00\x00\x00" b"\x94"
    b"\xe0\x87\x0e\xa9\xe2\x8f\x0f\xa9\xe4\x97\x10\xa9\xe6\x9f\x11\xa9"
)
# cbnz x1 ; cbz x0 — обязательный контекст перед arm64-гейтом CLI
ARM_CLI_CONTEXT = b"\x01\x00\x00\xb5" b"\x00\x00\x00\xb4"
ARM_CLI_FULL = ARM_CLI_CONTEXT + ARM_CLI_ORIG


class MachOTests(unittest.TestCase):
    def test_parse_thin_x64(self):
        blob = macho_thin(CPU_X64, CLI_SIG)
        info = fix.parse_binary(blob)
        self.assertEqual(info.kind, "macho")
        self.assertEqual(info.arch, "x64")
        self.assertEqual(info.slices[0].ranges, ((0, len(blob)),))

    def test_thin_x64_gate_roundtrip(self):
        blob = macho_thin(CPU_X64, b"\x90" * 16 + CLI_SIG)
        states = fix.scan_binary(fix.parse_binary(blob), blob)
        self.assertEqual(states[0].state, "original")
        self.assertEqual(states[0].offset, SIG_OFF + 16)

        data = bytearray(blob)
        fix.apply_gates(data, states)
        after = fix.scan_binary(fix.parse_binary(bytes(data)), bytes(data))
        self.assertEqual(after[0].state, "patched")

    def test_thin_arm64_gate_roundtrip(self):
        blob = macho_thin(CPU_ARM64, b"\x00" * 8 + ARM_CLI_FULL)
        states = fix.scan_binary(fix.parse_binary(blob), blob)
        self.assertEqual(states[0].gate.key, "cli-arm64")
        self.assertEqual(states[0].state, "original")

        data = bytearray(blob)
        fix.apply_gates(data, states)
        after = fix.scan_binary(fix.parse_binary(bytes(data)), bytes(data))
        self.assertEqual(after[0].state, "patched")

    def test_arm64_gate_requires_pointer_checks(self):
        # без контекста (cbnz x1; cbz x0) сигнатура игнорируется
        blob = macho_thin(CPU_ARM64, b"\x00" * 8 + ARM_CLI_ORIG)
        states = fix.scan_binary(fix.parse_binary(blob), blob)
        self.assertEqual(states[0].state, "absent")

        blob = macho_thin(CPU_ARM64, b"\x00" * 8 + ARM_CLI_FULL)
        states = fix.scan_binary(fix.parse_binary(blob), blob)
        self.assertEqual(states[0].state, "original")

    def test_arm64_context_predicate(self):
        data = ARM_CLI_CONTEXT + ARM_CLI_ORIG
        self.assertTrue(fix._cli_arm64_context(data, 8))
        self.assertFalse(fix._cli_arm64_context(data, 0))
        self.assertFalse(fix._cli_arm64_context(ARM_CLI_ORIG, 8))

    def test_universal_patches_both_slices(self):
        x64 = macho_thin(CPU_X64, b"\x90" * 8 + CLI_SIG)
        arm = macho_thin(CPU_ARM64, b"\x00" * 8 + ARM_CLI_FULL + HUB_SIG)
        blob = macho_fat([(CPU_X64, x64), (CPU_ARM64, arm)])

        info = fix.parse_binary(blob)
        self.assertEqual(info.arch, "universal(x64+arm64)")

        states = fix.scan_binary(info, blob)
        keys = {s.gate.key for s in states if s.state == "original"}
        # x64-слайс: cli + hub; arm64-слайс: cli-arm64
        self.assertIn("cli", keys)
        self.assertIn("cli-arm64", keys)

        data = bytearray(blob)
        fix.apply_gates(data, states)
        after = fix.scan_binary(fix.parse_binary(bytes(data)), bytes(data))
        self.assertTrue(after)
        self.assertTrue(all(s.state == "patched" for s in after if s.state != "absent"))

    def test_fat_offsets_are_absolute(self):
        x64 = macho_thin(CPU_X64, CLI_SIG)
        blob = macho_fat([(CPU_X64, x64)])
        info = fix.parse_binary(blob)
        states = fix.scan_binary(info, blob)
        self.assertGreater(states[0].offset or 0, 0x1000)

    def test_unknown_container_rejected(self):
        with self.assertRaises(fix.UnsupportedBinary):
            fix.parse_binary(b"PK\x03\x04" + b"\x00" * 200)


class MacBundleTests(unittest.TestCase):
    """Снапшот и восстановление подписи .app (codesign на Linux не вызывается)."""

    def _make_app(self, root):
        import plistlib
        app = Path(root) / "Fake.app"
        (app / "Contents" / "MacOS").mkdir(parents=True)
        (app / "Contents" / "_CodeSignature").mkdir()
        (app / "Contents" / "Info.plist").write_bytes(
            plistlib.dumps({"CFBundleExecutable": "fake"}))
        (app / "Contents" / "MacOS" / "fake").write_bytes(b"ORIGINAL-EXECUTABLE")
        (app / "Contents" / "CodeResources").write_bytes(b"orig-resources")
        (app / "Contents" / "_CodeSignature" / "CodeResources").write_bytes(b"orig-signature")
        return app

    def test_bundle_main_executable(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            app = self._make_app(tmp)
            main = fix._bundle_main_executable(app)
            self.assertIsNotNone(main)
            self.assertEqual(main.name, "fake")

    def test_snapshot_and_restore(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            app = self._make_app(tmp)
            store = fix.snapshot_bundle_signature(app)
            self.assertIsNotNone(store)
            self.assertTrue((store / "manifest.json").is_file())

            (app / "Contents" / "MacOS" / "fake").write_bytes(b"PATCHED")
            (app / "Contents" / "CodeResources").write_bytes(b"new")
            self.assertTrue(fix.restore_bundle_signature(app))
            self.assertEqual((app / "Contents" / "MacOS" / "fake").read_bytes(),
                             b"ORIGINAL-EXECUTABLE")
            self.assertEqual((app / "Contents" / "CodeResources").read_bytes(),
                             b"orig-resources")

    def test_snapshot_is_idempotent(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            app = self._make_app(tmp)
            first = fix.snapshot_bundle_signature(app)
            second = fix.snapshot_bundle_signature(app)
            self.assertEqual(first, second)

    def test_damaged_snapshot_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            app = self._make_app(tmp)
            store = fix.snapshot_bundle_signature(app)
            payload = store / "payload" / "Contents" / "CodeResources"
            payload.write_bytes(b"tampered")
            with self.assertRaises(fix.PatchError):
                fix.restore_bundle_signature(app)




class MacSignCommandTests(unittest.TestCase):
    """Проверяет, какой командой codesign подписывается бандл.

    На Linux сам codesign не вызывается, поэтому подменяем _cs и смотрим
    аргументы. Главное: для .app должна быть равномерная ad-hoc подпись
    с --deep и --options=0 (без Hardened Runtime), иначе Helper'ы падают
    с "different Team IDs".
    """

    class _Proc:
        returncode = 0
        stdout = b""

    def _run(self, app):
        calls = []
        target = Path("/tmp/Fake.app/Contents/Resources/bin/language_server") if app else Path("/tmp/agy")
        with mock.patch.object(fix.sys, "platform", "darwin"), \
             mock.patch.object(fix, "_codesign", return_value="/usr/bin/codesign"), \
             mock.patch.object(fix, "_cs", side_effect=lambda cmd, **kw: (calls.append(cmd), self._Proc())[1]), \
             mock.patch.object(fix, "_strip_quarantine", lambda t: None):
            fix.macos_sign(target, app, False)
        return calls

    def test_bundle_uses_deep_without_runtime(self):
        app = Path("/tmp/Fake.app")
        calls = self._run(app)
        sign = calls[0]
        self.assertIn("--deep", sign)
        self.assertIn("--options=0", sign)
        self.assertIn(str(app), sign)
        self.assertTrue(any("--verify" in c for c in calls[1:]))

    def test_standalone_keeps_metadata(self):
        calls = self._run(None)
        sign = calls[0]
        self.assertNotIn("--deep", sign)
        self.assertNotIn("--options=0", sign)
        self.assertTrue(any(a.startswith("--preserve-metadata") for a in sign))


if __name__ == "__main__":
    unittest.main(verbosity=2)
