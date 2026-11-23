#!/usr/bin/env python3
"""
antigravity-region-fix — адресный патч локального гейта доступности
Antigravity CLI (agy) и бэкендов Antigravity для Linux, macOS и Windows.

Что делает:
  * находит установленный agy и определяет его версию/архитектуру;
  * проверяет, что бинарник — PE, ELF или Mach-O (в т.ч. universal) известной
    архитектуры, и что сигнатуры гейтов уникальны (0 совпадений или >1 —
    отказ без записи);
  * сохраняет проверенную резервную копию оригинала;
  * атомарно меняет только байты локальной проверки hasValidAuth;
  * умеет откатываться и переживать обновление CLI.

Чего НЕ делает:
  * не трогает TLS, сертификаты, DNS, прокси;
  * не читает и не логирует OAuth-токены;
  * не ходит в сеть;
  * не подменяет серверный ответ: если Google отклонит запрос к модели,
    CLI покажет именно серверную ошибку.

Только стандартная библиотека Python 3.8+.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

if os.name != "nt":
    import fcntl
else:
    import msvcrt

TOOL = "antigravity-region-fix"
TOOL_VERSION = "1.2.1"
MANIFEST_SCHEMA = 1

# --------------------------------------------------------------------------
# PE, ELF и Mach-O
# --------------------------------------------------------------------------

EM_X86_64 = 0x3E
EM_AARCH64 = 0xB7
PT_LOAD = 1
PF_X = 0x1

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
LC_SEGMENT_64 = 0x19
VM_PROT_EXECUTE = 0x4
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
PE_MACHINE_X86_64 = 0x8664
PE_MACHINE_ARM64 = 0xAA64
IMAGE_SCN_MEM_EXECUTE = 0x20000000


class PatchError(Exception):
    """Ошибка, при которой запись в бинарник запрещена."""


class UnsupportedBinary(PatchError):
    pass


class SignatureError(PatchError):
    pass


@dataclass(frozen=True)
class ElfInfo:
    machine: int
    bits: int
    endian: str
    exec_ranges: Tuple[Tuple[int, int], ...]

    @property
    def arch(self) -> str:
        if self.machine == EM_X86_64:
            return "x64"
        if self.machine == EM_AARCH64:
            return "arm64"
        return "unknown:0x%x" % self.machine


def parse_elf(data: bytes) -> ElfInfo:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise UnsupportedBinary("файл не является ELF-бинарником")
    if data[4] != 2:
        raise UnsupportedBinary("поддерживается только ELF64 (class=%d)" % data[4])
    if data[5] != 1:
        raise UnsupportedBinary("поддерживается только little-endian ELF")

    machine = struct.unpack_from("<H", data, 18)[0]
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]

    if e_phoff <= 0 or e_phentsize < 56 or e_phnum <= 0:
        raise UnsupportedBinary("повреждённая таблица program headers")

    ranges: List[Tuple[int, int]] = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 56 > len(data):
            raise UnsupportedBinary("program header выходит за пределы файла")
        p_type, p_flags = struct.unpack_from("<II", data, off)
        p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack_from("<QQQQ", data, off + 8)
        if p_type == PT_LOAD and (p_flags & PF_X) and p_filesz:
            start = p_offset
            end = min(p_offset + p_filesz, len(data))
            if start < end:
                ranges.append((start, end))

    if not ranges:
        raise UnsupportedBinary("в ELF нет исполняемых сегментов")

    ranges.sort()
    return ElfInfo(machine=machine, bits=64, endian="little", exec_ranges=tuple(ranges))


@dataclass(frozen=True)
class Slice:
    """Один код-слайс: PE/ELF или одна архитектура внутри universal."""
    arch: str
    ranges: Tuple[Tuple[int, int], ...]
    base: int
    size: int


@dataclass(frozen=True)
class BinaryInfo:
    kind: str                       # "pe" | "elf" | "macho"
    slices: Tuple[Slice, ...]

    @property
    def arch(self) -> str:
        archs: List[str] = []
        for sl in self.slices:
            if sl.arch not in archs:
                archs.append(sl.arch)
        if len(archs) == 1:
            return archs[0]
        return "universal(%s)" % "+".join(archs)


def _cpu_arch(cputype: int) -> str:
    cputype &= 0xFFFFFFFF
    if cputype == CPU_TYPE_X86_64:
        return "x64"
    if cputype == CPU_TYPE_ARM64:
        return "arm64"
    return "unknown:0x%x" % cputype


def _arch_from_machine(machine: int) -> str:
    if machine == EM_X86_64:
        return "x64"
    if machine == EM_AARCH64:
        return "arm64"
    return "unknown:0x%x" % machine


def _parse_macho_thin(data: bytes, base: int, size: int) -> Slice:
    if base < 0 or size <= 0 or base + size > len(data) or base + 32 > len(data):
        raise UnsupportedBinary("слайс Mach-O выходит за пределы файла")
    magic = struct.unpack_from("<I", data, base)[0]
    if magic == MH_MAGIC_64:
        endian = "<"
    elif magic == MH_CIGAM_64:
        endian = ">"
    else:
        raise UnsupportedBinary("неизвестный magic Mach-O: 0x%08x" % magic)

    cputype = struct.unpack_from(endian + "i", data, base + 4)[0]
    ncmds = struct.unpack_from(endian + "I", data, base + 16)[0]
    sizeofcmds = struct.unpack_from(endian + "I", data, base + 20)[0]

    off = base + 32
    cmds_end = min(off + sizeofcmds, base + size)
    if ncmds <= 0 or ncmds > 100000 or sizeofcmds <= 0:
        raise UnsupportedBinary("повреждённые load commands Mach-O")

    ranges: List[Tuple[int, int]] = []
    for _ in range(ncmds):
        if off + 8 > cmds_end:
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
        if cmdsize < 8 or off + cmdsize > cmds_end:
            raise UnsupportedBinary("некорректный cmdsize в Mach-O")
        # LC_SEGMENT_64: cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8)
        #                 fileoff(8) filesize(8) maxprot(4) initprot(4) ...
        if cmd == LC_SEGMENT_64 and cmdsize >= 72:
            fileoff, filesize = struct.unpack_from(endian + "QQ", data, off + 40)
            initprot = struct.unpack_from(endian + "i", data, off + 60)[0]
            if (initprot & VM_PROT_EXECUTE) and filesize:
                start = base + fileoff
                end = min(base + fileoff + filesize, base + size)
                if 0 <= start < end <= len(data):
                    ranges.append((start, end))
        off += cmdsize

    if not ranges:
        raise UnsupportedBinary("в Mach-O нет исполняемых сегментов")

    ranges.sort()
    return Slice(arch=_cpu_arch(cputype), ranges=tuple(ranges), base=base, size=size)


def _parse_macho(data: bytes) -> Optional[BinaryInfo]:
    if len(data) < 8:
        return None
    be_magic = struct.unpack_from(">I", data, 0)[0]
    le_magic = struct.unpack_from("<I", data, 0)[0]

    if be_magic in (FAT_MAGIC, FAT_MAGIC_64):
        nfat = struct.unpack_from(">I", data, 4)[0]
        if nfat <= 0 or nfat > 64:
            return None
        entsize, layout = (20, ">IIIII") if be_magic == FAT_MAGIC else (32, ">IIQQII")
        slices: List[Slice] = []
        for i in range(nfat):
            off = 8 + i * entsize
            if off + entsize > len(data):
                raise UnsupportedBinary("fat-заголовок Mach-O выходит за пределы файла")
            if be_magic == FAT_MAGIC:
                _cpu, _sub, s_off, s_size, _align = struct.unpack_from(layout, data, off)
            else:
                _cpu, _sub, s_off, s_size, _align, _res = struct.unpack_from(layout, data, off)
            slices.append(_parse_macho_thin(data, s_off, s_size))
        if not slices:
            raise UnsupportedBinary("fat-бинарник не содержит слайсов")
        return BinaryInfo(kind="macho", slices=tuple(slices))

    if le_magic in (MH_MAGIC_64, MH_CIGAM_64):
        return BinaryInfo(kind="macho", slices=(_parse_macho_thin(data, 0, len(data)),))

    return None


def _parse_pe(data: bytes) -> Optional[BinaryInfo]:
    if data[:2] != b"MZ":
        return None
    if len(data) < 0x40:
        raise UnsupportedBinary("повреждённый заголовок PE")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise UnsupportedBinary("заголовок PE выходит за пределы файла")
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise UnsupportedBinary("неверная сигнатура PE")

    machine, section_count = struct.unpack_from("<HH", data, pe_offset + 4)
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    if section_count <= 0 or section_count > 96 or optional_size < 2:
        raise UnsupportedBinary("повреждённая таблица секций PE")

    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(data):
        raise UnsupportedBinary("optional header PE выходит за пределы файла")
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    if machine in (PE_MACHINE_X86_64, PE_MACHINE_ARM64) and optional_magic != 0x20B:
        raise UnsupportedBinary("для PE x64/arm64 требуется заголовок PE32+")

    section_table = optional_offset + optional_size
    section_table_end = section_table + section_count * 40
    if section_table_end > len(data):
        raise UnsupportedBinary("таблица секций PE выходит за пределы файла")

    ranges: List[Tuple[int, int]] = []
    for i in range(section_count):
        offset = section_table + i * 40
        raw_size, raw_offset = struct.unpack_from("<II", data, offset + 16)
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        if not (characteristics & IMAGE_SCN_MEM_EXECUTE) or not raw_size:
            continue
        end = raw_offset + raw_size
        if raw_offset < section_table_end or end > len(data):
            raise UnsupportedBinary("исполняемая секция PE выходит за пределы файла")
        ranges.append((raw_offset, end))

    if not ranges:
        raise UnsupportedBinary("в PE нет исполняемых секций")

    ranges.sort()
    merged: List[Tuple[int, int]] = []
    for start, end in ranges:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    arch = {
        PE_MACHINE_X86_64: "x64",
        PE_MACHINE_ARM64: "arm64",
    }.get(machine, "unknown:0x%x" % machine)
    sl = Slice(arch=arch, ranges=tuple(merged), base=0, size=len(data))
    return BinaryInfo(kind="pe", slices=(sl,))


def parse_binary(data: bytes) -> BinaryInfo:
    """Определяет PE, ELF или Mach-O, архитектуру и исполняемые диапазоны."""
    pe = _parse_pe(data)
    if pe is not None:
        return pe

    if data[:4] == b"\x7fELF":
        elf = parse_elf(data)
        sl = Slice(arch=_arch_from_machine(elf.machine), ranges=elf.exec_ranges,
                   base=0, size=len(data))
        return BinaryInfo(kind="elf", slices=(sl,))

    macho = _parse_macho(data)
    if macho is not None:
        return macho

    raise UnsupportedBinary("неизвестный формат: ожидался PE, ELF или Mach-O")


# --------------------------------------------------------------------------
# Гейты
# --------------------------------------------------------------------------
#
# Найдено в agy 1.5.13 / 1.5.14 (Fedora, x86-64), подтверждено дизассемблером
# и экспериментом:
#
#   handleAuthResult (CLI):
#       test rcx,rcx ; je ... ; cmp byte ptr [rcx+8],0 ; jne eligible
#   Проверка заменяется на повторный test rcx,rcx + NOP: rcx здесь не ноль,
#   поэтому jne всегда уводит в ветку "eligible".
#
#   PersonalAuthValidator (режим agy --hub, его использует IDE):
#       cmp byte ptr [rax+8],0 ; je ... ; mov rdx,[rsp+0x70] ; mov [rax+0x60],rdx
#   Заменяется на mov byte ptr [rax+8],1 ; nop ; nop: флаг hasValidAuth = true,
#   условный переход исчезает.
#
# Байт-смещения не фиксируются: каждая сигнатура сначала ищется регулярным
# выражением в исполняемых сегментах, и патч применяется только при ровно
# одном однозначном совпадении.


@dataclass(frozen=True)
class Lit:
    """Точная последовательность байтов (экранируется как литерал)."""
    data: bytes


@dataclass(frozen=True)
class Wild:
    """Несколько произвольных байтов."""
    n: int = 1


@dataclass(frozen=True)
class Alt:
    """Один байт из заданного набора."""
    choices: bytes


def _compile(items: Sequence[object]) -> "re.Pattern[bytes]":
    """Собирает regex из структурных элементов.

    Важно: литеральные байты экранируются. Иначе, например, \\x24 попадёт
    в шаблон как '$' и превратится в якорь конца строки.
    """
    out = bytearray()
    for item in items:
        if isinstance(item, Lit):
            out += re.escape(item.data)
        elif isinstance(item, Wild):
            out += b"." * item.n
        elif isinstance(item, Alt):
            out += b"[" + b"".join(re.escape(bytes([b])) for b in item.choices) + b"]"
        else:
            raise TypeError("неизвестный элемент сигнатуры: %r" % (item,))
    return re.compile(bytes(out), re.DOTALL)


class Gate:
    def __init__(self, key: str, label: str, arch: str,
                 original: Sequence[object], patched: Sequence[object],
                 fix: bytes, fix_offset: int,
                 verified: bool = True, note: str = "",
                 accept: Optional[Callable[[bytes, int], bool]] = None) -> None:
        self.key = key
        self.label = label
        self.arch = arch
        self.original_rx = _compile(original)
        self.patched_rx = _compile(patched)
        self.fix = fix
        self.fix_offset = fix_offset
        self.verified = verified
        self.note = note
        self.accept = accept

    def __repr__(self) -> str:
        return "<Gate %s (%s)>" % (self.key, self.arch)


def _cli_arm64_context(data: bytes, offset: int) -> bool:
    """Отсекает ложные совпадения arm64-сигнатуры CLI.

    Перед гейтом компилятор ставит проверку указателя:
        cbnz x1, ...      ; 0xB5000001
        cbz  x0, ...      ; 0xB4000000
    Требуем обе инструкции ровно перед сигнатурой (как в upstream).
    """
    if offset < 8:
        return False
    w1 = struct.unpack_from("<I", data, offset - 8)[0]
    w0 = struct.unpack_from("<I", data, offset - 4)[0]
    return (w1 & 0xFF00001F) == 0xB5000001 and (w0 & 0xFF00001F) == 0xB4000000


GATES: Tuple[Gate, ...] = (
    Gate(
        key="cli",
        label="CLI eligibility screen (handleAuthResult)",
        arch="x64",
        original=[
            Lit(b"\x48\x85\xc9\x0f\x84"), Wild(4),
            Lit(b"\x80\x79\x08\x00\x0f\x85"), Wild(4),
            Lit(b"\x48\x89\xc8\x90\xe8"), Wild(4),
            Lit(b"\x48\x89\x84\x24\xe0\x00\x00\x00"),
            Lit(b"\x48\x89\x9c\x24\xe8\x00\x00\x00"),
            Lit(b"\x48\x89\x8c\x24\xf0\x00\x00\x00"),
        ],
        patched=[
            Lit(b"\x48\x85\xc9\x0f\x84"), Wild(4),
            Lit(b"\x48\x85\xc9\x90\x0f\x85"), Wild(4),
            Lit(b"\x48\x89\xc8\x90\xe8"), Wild(4),
            Lit(b"\x48\x89\x84\x24\xe0\x00\x00\x00"),
            Lit(b"\x48\x89\x9c\x24\xe8\x00\x00\x00"),
            Lit(b"\x48\x89\x8c\x24\xf0\x00\x00\x00"),
        ],
        fix=b"\x48\x85\xc9\x90",
        fix_offset=9,
        note="проверено на 1.5.13 и 1.5.14",
    ),
    Gate(
        key="hub",
        label="IDE/hub auth validator (hasValidAuth)",
        arch="x64",
        original=[
            Lit(b"\x80\x78\x08\x00\x74"), Wild(1),
            Lit(b"\x48\x8b\x54\x24\x70\x48\x89\x50\x60"),
        ],
        patched=[
            Lit(b"\xc6\x40\x08\x01\x90\x90"),
            Lit(b"\x48\x8b\x54\x24\x70\x48\x89\x50\x60"),
        ],
        fix=b"\xc6\x40\x08\x01\x90\x90",
        fix_offset=0,
        note="проверено на 1.5.13, 1.5.14 и бэкенде IDE 1.5.2",
    ),
    Gate(
        key="cli-arm64",
        label="CLI eligibility screen (arm64)",
        arch="arm64",
        original=[
            Lit(b"\x02\x20\x40\x39"),
            Alt(b"\x02\x22\x42\x62\x82\xa2\xc2\xe2"), Wild(1),
            Alt(bytes(range(0x00, 0x08))), Lit(b"\x37"), Wild(3),
            Alt(b"\x94\x95\x96\x97"),
            Lit(b"\xe0\x87\x0e\xa9\xe2\x8f\x0f\xa9\xe4\x97\x10\xa9\xe6\x9f\x11\xa9"),
        ],
        patched=[
            Lit(b"\x22\x00\x80\x52"),
            Alt(b"\x02\x22\x42\x62\x82\xa2\xc2\xe2"), Wild(1),
            Alt(bytes(range(0x00, 0x08))), Lit(b"\x37"), Wild(3),
            Alt(b"\x94\x95\x96\x97"),
            Lit(b"\xe0\x87\x0e\xa9\xe2\x8f\x0f\xa9\xe4\x97\x10\xa9\xe6\x9f\x11\xa9"),
        ],
        fix=b"\x22\x00\x80\x52",
        fix_offset=0,
        verified=False,
        accept=_cli_arm64_context,
        note="сигнатура upstream, на этой машине (x86-64) не проверялась",
    ),
    Gate(
        key="hub-arm64",
        label="IDE/hub auth validator (arm64)",
        arch="arm64",
        original=[
            Lit(b"\x03\x20\x40\x39"),
            Alt(b"\x03\x23\x43\x63\x83\xa3\xc3\xe3"), Wild(1),
            Alt(bytes(range(0x00, 0x08))), Lit(b"\x36"),
            Lit(b"\xe3\x13\x48\xa9\x03\x10\x06\xa9"),
        ],
        patched=[
            Lit(b"\x23\x00\x80\x52\x03\x20\x00\x39"),
            Lit(b"\xe3\x13\x48\xa9\x03\x10\x06\xa9"),
        ],
        fix=b"\x23\x00\x80\x52\x03\x20\x00\x39",
        fix_offset=0,
        verified=False,
        note="сигнатура upstream, на этой машине (x86-64) не проверялась",
    ),
)

GATE_INDEX: Dict[str, Gate] = {g.key: g for g in GATES}


def _find_in_ranges(rx: "re.Pattern[bytes]", data: bytes,
                    ranges: Sequence[Tuple[int, int]],
                    accept: Optional[Callable[[bytes, int], bool]] = None) -> List[int]:
    found: List[int] = []
    for start, end in ranges:
        pos = start
        while pos < end:
            m = rx.search(data, pos, end)
            if not m:
                break
            if accept is None or accept(data, m.start()):
                if not found or found[-1] != m.start():
                    found.append(m.start())
            pos = max(m.end(), m.start() + 1)
    return found


@dataclass
class GateState:
    gate: Gate
    state: str            # original | patched | mixed | ambiguous | absent
    offset: Optional[int] = None
    detail: str = ""


def scan_gates(data: bytes, ranges: Sequence[Tuple[int, int]], gates: Iterable[Gate]) -> List[GateState]:
    out: List[GateState] = []
    for gate in gates:
        orig = _find_in_ranges(gate.original_rx, data, ranges, gate.accept)
        pat = _find_in_ranges(gate.patched_rx, data, ranges, gate.accept)
        if orig and pat:
            out.append(GateState(gate, "mixed", None,
                                 "одновременно найдены исходная и пропатченная сигнатуры"))
        elif len(orig) > 1:
            out.append(GateState(gate, "ambiguous", None,
                                 "исходная сигнатура встречается %d раз" % len(orig)))
        elif len(pat) > 1:
            out.append(GateState(gate, "ambiguous", None,
                                 "пропатченная сигнатура встречается %d раз" % len(pat)))
        elif pat:
            out.append(GateState(gate, "patched", pat[0]))
        elif orig:
            out.append(GateState(gate, "original", orig[0]))
        else:
            out.append(GateState(gate, "absent", None))
    return out


def scan_binary(info: BinaryInfo, data: bytes) -> List[GateState]:
    """Сканирует каждый слайс сигнатурами его архитектуры."""
    out: List[GateState] = []
    for sl in info.slices:
        gates = [g for g in GATES if g.arch == sl.arch]
        if gates:
            out.extend(scan_gates(data, sl.ranges, gates))
    return out


def apply_gates(data: bytearray, states: Sequence[GateState]) -> List[GateState]:
    """Применяет исправления in-place; возвращает только изменённые гейты."""
    changed: List[GateState] = []
    for st in states:
        if st.state != "original":
            continue
        gate = st.gate
        assert st.offset is not None
        at = st.offset + gate.fix_offset
        # сигнатура уже найдена по этому смещению; убеждаемся, что патч
        # действительно меняет байты, а не совпадает с ними
        if bytes(data[at:at + len(gate.fix)]) == gate.fix:
            continue
        data[at:at + len(gate.fix)] = gate.fix
        changed.append(st)
    return changed


# --------------------------------------------------------------------------
# Файлы, хэши, состояние
# --------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def state_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    path = Path(base) / TOOL
    path.mkdir(parents=True, exist_ok=True)
    return path


def backup_dir() -> Path:
    path = state_dir() / "backups"
    path.mkdir(parents=True, exist_ok=True)
    return path


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    directory = path.parent
    fd, tmp_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=str(directory))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        try:
            dfd = os.open(str(directory), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _macos_write_hint(path: Path, exc: OSError) -> str:
    msg = "запись в %s не удалась: %s" % (path, exc)
    if sys.platform == "darwin" and _find_app_bundle(path) is not None:
        msg += (
            "\nmacOS блокирует изменение файлов внутри чужих приложений "
            "(TCC, «Управление приложениями»). sudo здесь не помогает.\n"
            "Выдайте разрешение терминалу:\n"
            "  Системные настройки → Конфиденциальность и безопасность → "
            "Управление приложениями\n"
            "  → «+» → Программы → Утилиты → Terminal → включить.\n"
            "macOS может перезапустить терминал — откройте его снова и "
            "повторите команду."
        )
    return msg


def write_target(path: Path, data: bytes, mode: int) -> None:
    """Запись в целевой файл с понятной подсказкой на macOS."""
    try:
        atomic_write(path, data, mode)
    except PermissionError as exc:
        raise PatchError(_macos_write_hint(path, exc)) from exc


def is_binary_running(path: Path) -> List[int]:
    real = os.path.normcase(os.path.realpath(path))
    pids: List[int] = []
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class ProcessEntry(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
        kernel32.Process32FirstW.restype = wintypes.BOOL
        kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
        kernel32.Process32NextW.restype = wintypes.BOOL
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
        ]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            return pids
        try:
            entry = ProcessEntry()
            entry.dwSize = ctypes.sizeof(entry)
            found = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while found:
                pid = int(entry.th32ProcessID)
                if pid != os.getpid():
                    process = kernel32.OpenProcess(0x1000, False, pid)
                    if process:
                        try:
                            image = ctypes.create_unicode_buffer(32768)
                            size = wintypes.DWORD(len(image))
                            if kernel32.QueryFullProcessImageNameW(
                                process, 0, image, ctypes.byref(size)
                            ) and os.path.normcase(os.path.realpath(image.value)) == real:
                                pids.append(pid)
                        finally:
                            kernel32.CloseHandle(process)
                found = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)
        return pids

    proc = Path("/proc")
    if not proc.is_dir():
        return pids
    me = os.getpid()
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == me:
            continue
        try:
            target = os.readlink(entry / "exe")
        except OSError:
            continue
        if target.endswith(" (deleted)"):
            target = target[: -len(" (deleted)")]
        if os.path.normcase(os.path.realpath(target)) == real:
            pids.append(pid)
    return pids


# --------------------------------------------------------------------------
# Версия и цели
# --------------------------------------------------------------------------

VERSION_RE = re.compile(r"\b(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)\b")


def _asar_read(asar: Path, inner: str) -> Optional[bytes]:
    """Читает один файл из Electron asar без внешних зависимостей."""
    try:
        with open(asar, "rb") as fh:
            head = fh.read(16)
            if len(head) < 16:
                return None
            json_len = struct.unpack_from("<I", head, 12)[0]
            header = json.loads(fh.read(json_len).decode("utf-8"))
            node = header
            for part in inner.split("/"):
                node = node["files"][part]
            offset, size = int(node["offset"]), int(node["size"])
            base = 16 + json_len
            fh.seek(base + offset)
            return fh.read(size)
    except (OSError, ValueError, KeyError, struct.error):
        return None


def _version_from_asar(binary: Path) -> Optional[str]:
    """Версия приложения из resources/app.asar (для language_server)."""
    asar = binary.parent.parent / "app.asar"
    if not asar.is_file():
        return None
    raw = _asar_read(asar, "package.json")
    if not raw:
        return None
    try:
        return str(json.loads(raw.decode("utf-8")).get("version") or "") or None
    except ValueError:
        return None


def detect_version(path: Path, data: Optional[bytes] = None) -> str:
    """Версия из sibling-манифеста установщика, asar приложения, иначе `--version`."""
    sidecar = path.parent / (path.name + ".version.json")
    try:
        if sidecar.is_file():
            version = json.loads(sidecar.read_text("utf-8")).get("version")
            if version:
                return str(version)
    except (OSError, ValueError):
        pass

    from_asar = _version_from_asar(path)
    if from_asar:
        return from_asar

    cli_name = "agy.exe" if os.name == "nt" else "agy"
    if os.path.normcase(path.name) != cli_name:
        # language_server и прочие бэкенды не понимают `-p`/`--version`
        return "unknown"

    try:
        proc = subprocess.run(
            [str(path), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=25,
            env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
        )
        text = proc.stdout.decode("utf-8", "replace")
        for line in text.splitlines():
            m = VERSION_RE.search(line)
            if m:
                return m.group(1)
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def app_targets() -> List[Path]:
    """Известные бэкенды приложений Antigravity (Linux и macOS)."""
    home = Path.home()
    candidates = [
        # Linux: Antigravity App
        home / ".local" / "opt" / "antigravity-app" / "Antigravity-x64"
             / "resources" / "bin" / "language_server",
        # macOS: Antigravity.app
        Path("/Applications/Antigravity.app/Contents/Resources/bin/language_server"),
        home / "Applications" / "Antigravity.app" / "Contents" / "Resources"
             / "bin" / "language_server",
        # бэкенд hub, который использует расширение в Antigravity IDE
        home / ".gemini" / "bin" / "agy",
    ]
    out: List[Path] = []
    seen = set()
    for c in candidates:
        if not c.is_file():
            continue
        real = os.path.realpath(c)
        if real in seen:
            continue
        seen.add(real)
        out.append(c)
    return out


def default_targets(all_targets: bool, include_apps: bool = False) -> List[Path]:
    candidates: List[Path] = []
    which = shutil.which("agy.exe" if os.name == "nt" else "agy")
    if which:
        candidates.append(Path(which))
    home = Path.home()
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            candidates.append(Path(local_app_data) / "agy" / "bin" / "agy.exe")
        if all_targets or include_apps:
            candidates.append(home / ".gemini" / "bin" / "agy.exe")
    else:
        candidates.append(home / ".local" / "bin" / "agy")
        if sys.platform == "darwin":
            candidates.append(Path("/usr/local/bin/agy"))
            candidates.append(Path("/opt/homebrew/bin/agy"))
        if all_targets or include_apps:
            candidates.extend(app_targets())
    out: List[Path] = []
    seen = set()
    for c in candidates:
        if not c.exists() or not c.is_file():
            continue
        real = os.path.normcase(os.path.realpath(c))
        if real in seen:
            continue
        seen.add(real)
        out.append(c)
    return out


# --------------------------------------------------------------------------
# Осмотр и патч
# --------------------------------------------------------------------------

@dataclass
class Inspection:
    path: Path
    data: bytes
    binfo: BinaryInfo
    version: str
    gates: List[GateState]
    sha256: str

    @property
    def arch(self) -> str:
        return self.binfo.arch

    @property
    def relevant_gates(self) -> List[GateState]:
        # gates уже отфильтрованы по слайсам в scan_binary
        return self.gates

    @property
    def present(self) -> List[GateState]:
        return [g for g in self.relevant_gates if g.state != "absent"]

    @property
    def original(self) -> List[GateState]:
        return [g for g in self.present if g.state == "original"]

    @property
    def patched(self) -> List[GateState]:
        return [g for g in self.present if g.state == "patched"]

    @property
    def broken(self) -> List[GateState]:
        return [g for g in self.present if g.state in ("mixed", "ambiguous")]

    @property
    def overall(self) -> str:
        if not self.present:
            return "unsupported"
        if self.broken:
            return "broken"
        if self.patched and not self.original:
            return "patched"
        if self.original and not self.patched:
            return "original"
        return "partial"


def inspect(path: Path) -> Inspection:
    data = path.read_bytes()
    binfo = parse_binary(data)
    gates = scan_binary(binfo, data)
    version = detect_version(path, data)
    return Inspection(path=path, data=data, binfo=binfo, version=version,
                      gates=gates, sha256=sha256_bytes(data))


def ensure_writable(path: Path) -> None:
    if not os.access(str(path.parent), os.W_OK) or not os.access(str(path), os.W_OK):
        if os.name == "nt":
            raise PatchError("нет прав на запись в %s. Проверьте права учётной записи Windows." % path)
        raise PatchError(
            "нет прав на запись в %s. Запустите через sudo или исправьте владельца." % path
        )


def find_backup(path: Path, version: Optional[str] = None,
                explicit: Optional[Path] = None) -> Tuple[Path, dict]:
    if explicit is not None:
        manifest = explicit.with_suffix(explicit.suffix + ".json")
        if not explicit.is_file() or not manifest.is_file():
            raise PatchError("резервная копия или манифест не найдены: %s" % explicit)
        return explicit, json.loads(manifest.read_text("utf-8"))

    manifests = sorted(backup_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    real = os.path.realpath(path)
    compatible: List[Tuple[Path, dict]] = []
    for mpath in manifests:
        try:
            meta = json.loads(mpath.read_text("utf-8"))
        except (OSError, ValueError):
            continue
        if os.path.realpath(meta.get("source", "")) != real:
            continue
        backup = Path(meta.get("backup", ""))
        if not backup.is_file():
            continue
        if version and meta.get("version") != version:
            continue
        compatible.append((backup, meta))
    if not compatible:
        raise PatchError(
            "для %s нет резервной копии%s" % (path, " версии %s" % version if version else "")
        )
    return compatible[0]


def create_backup(path: Path, data: bytes, insp: Inspection) -> Tuple[Path, dict]:
    digest = insp.sha256
    stem = "%s-%s-%s" % (path.name, insp.version, digest[:12])
    target = backup_dir() / (stem + ".orig")
    manifest = backup_dir() / (stem + ".json")

    existing = [p for p in backup_dir().glob("*.json")
                if p.is_file() and json.loads(p.read_text("utf-8")).get("sha256") == digest]
    if existing:
        try:
            meta = json.loads(existing[0].read_text("utf-8"))
            backup = Path(meta["backup"])
            if backup.is_file() and sha256_file(backup) == digest:
                return backup, meta
        except (OSError, ValueError, KeyError):
            pass

    meta = {
        "schema": MANIFEST_SCHEMA,
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "source": str(path),
        "backup": str(target),
        "sha256": digest,
        "size": len(data),
        "version": insp.version,
        "arch": insp.arch,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "gates": {g.gate.key: g.state for g in insp.present},
    }
    atomic_write(target, data, 0o755)
    if sha256_file(target) != digest:
        raise PatchError("резервная копия повреждена при записи: %s" % target)
    atomic_write(manifest, json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"), 0o644)
    return target, meta


def verify_backup_is_original(backup: Path, meta: dict) -> None:
    digest = sha256_file(backup)
    if digest != meta.get("sha256"):
        raise PatchError("резервная копия не совпадает с манифестом (sha256): %s" % backup)
    data = backup.read_bytes()
    binfo = parse_binary(data)
    states = scan_binary(binfo, data)
    for st in states:
        if st.state == "patched":
            raise PatchError("резервная копия уже содержит патч (%s): %s" % (st.gate.key, backup))


SIGN_BAK_SUFFIX = ".agysignbak"


def _codesign() -> Optional[str]:
    return shutil.which("codesign")


def _cs(args: Sequence[str], timeout: int = 300) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run(list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout)


def _last_line(blob: bytes) -> str:
    lines = blob.decode("utf-8", "replace").strip().splitlines()
    return lines[-1] if lines else "без вывода"


def _find_app_bundle(path: Path) -> Optional[Path]:
    for parent in [path] + list(path.parents):
        if parent.suffix == ".app":
            return parent
    return None


def _bundle_main_executable(app: Path) -> Optional[Path]:
    try:
        import plistlib
        info = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    except (OSError, ValueError, KeyError):
        return None
    name = info.get("CFBundleExecutable")
    if not name:
        return None
    candidate = app / "Contents" / "MacOS" / str(name)
    return candidate if candidate.is_file() else None


def _sign_snapshot_dir(app: Path) -> Path:
    return app.parent / (app.name + SIGN_BAK_SUFFIX)


def snapshot_bundle_signature(app: Path) -> Optional[Path]:
    """Сохраняет оригинальную подпись бандла до первой правки.

    Правка вложенного бинарника ломает печать CodeResources, поэтому для
    полного отката нужно вернуть не только бинарник, но и саму подпись.
    """
    store = _sign_snapshot_dir(app)
    manifest = store / "manifest.json"
    if manifest.is_file():
        return store

    items: List[Tuple[Path, str]] = []
    main = _bundle_main_executable(app)
    if main is not None:
        items.append((main, "main-executable"))
    signature = app / "Contents" / "_CodeSignature"
    if signature.is_dir():
        for path in sorted(signature.rglob("*")):
            if path.is_file():
                items.append((path, "code-signature"))
    resources = app / "Contents" / "CodeResources"
    if resources.is_file():
        items.append((resources, "code-resources"))
    if not items:
        return None

    entries = []
    for src, kind in items:
        rel = src.relative_to(app)
        dst = store / "payload" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(dst, src.read_bytes(), 0o644)
        entries.append({"rel": str(rel), "kind": kind, "sha256": sha256_file(dst)})

    meta = {
        "schema": 1,
        "app": str(app),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "items": entries,
    }
    atomic_write(manifest, json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"), 0o644)
    ok("снапшот подписи бандла: %s" % store)
    return store


def restore_bundle_signature(app: Path) -> bool:
    store = _sign_snapshot_dir(app)
    manifest = store / "manifest.json"
    if not manifest.is_file():
        return False
    try:
        meta = json.loads(manifest.read_text("utf-8"))
    except (OSError, ValueError):
        return False

    for item in meta.get("items", []):
        src = store / "payload" / item["rel"]
        dst = app / item["rel"]
        if not src.is_file():
            raise PatchError("снапшот подписи неполный: %s" % src)
        data = src.read_bytes()
        if sha256_bytes(data) != item.get("sha256"):
            raise PatchError("снапшот подписи повреждён: %s" % src)
        dst.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(dst, data, 0o755 if item.get("kind") == "main-executable" else 0o644)

    cs = _codesign()
    if cs:
        proc = _cs([cs, "--verify", "--deep", "--strict", str(app)])
        if proc.returncode != 0:
            warn("подпись восстановлена, но проверка не прошла: %s" % _last_line(proc.stdout))
            return False
    ok("подпись бандла восстановлена: %s" % app)
    return True


def _strip_quarantine(target: Path) -> None:
    xattr = shutil.which("xattr")
    if not xattr or sys.platform != "darwin":
        return
    _cs([xattr, "-dr", "com.apple.quarantine", str(target)])


def macos_sign(path: Path, app: Optional[Path], allow_libval: bool) -> bool:
    """Переподписывает изменённый Mach-O и, если нужно, весь .app.

    Для бандла подпись делается равномерно ad-hoc с --options=0. Это снимает
    Hardened Runtime, а вместе с ним Library Validation у всех процессов,
    включая Helper'ы. Иначе Helper'ы сохраняют подпись Google со своим Team ID
    и отказываются загружать ad-hoc Electron Framework — приложение падает на
    старте с «mapping process and mapped file (non-platform) have different
    Team IDs». Entitlement disable-library-validation только главному файлу
    этой проблемы не решает.
    """
    cs = _codesign()
    if not cs:
        if sys.platform == "darwin":
            raise PatchError("codesign не найден: macOS не запустит изменённый файл")
        warn("Mach-O изменён вне macOS: подпись нужно обновить на Mac "
             "(codesign --force --deep --sign - --options=0 <путь>)")
        return False

    if allow_libval:
        warn("--macos-disable-library-validation больше не требуется: "
             "бандл подписывается без Hardened Runtime")

    if app:
        proc = _cs([cs, "--force", "--deep", "--sign", "-", "--options=0", str(app)])
    else:
        proc = _cs([cs, "--force", "--sign", "-", "--timestamp=none",
                    "--preserve-metadata=identifier,entitlements,flags,runtime", str(path)])
    if proc.returncode != 0:
        raise PatchError("codesign не смог подписать %s: %s" %
                         (app or path, _last_line(proc.stdout)))

    verify = [cs, "--verify", "--strict"]
    if app:
        verify.insert(2, "--deep")
    proc = _cs(verify + [str(app or path)])
    if proc.returncode != 0:
        raise PatchError("проверка подписи не прошла: %s" % _last_line(proc.stdout))

    _strip_quarantine(app or path)
    ok("подпись обновлена (ad-hoc%s): %s" %
       (", без Hardened Runtime" if app else "", app or path))
    return True


def patch_one(path: Path, args: argparse.Namespace) -> int:
    insp = inspect(path)
    print_target_header(insp)

    if insp.broken:
        for st in insp.broken:
            err("%s: %s" % (st.gate.label, st.detail))
        err("смешанное/неоднозначное состояние — запись отменена")
        return 2

    if not insp.present:
        err("ни одна сигнатура гейта не найдена для %s (%s, версия %s)" %
            (path, insp.arch, insp.version))
        err("это может быть новая версия CLI. Проверьте проект на обновление сигнатур.")
        return 2

    if insp.overall == "patched":
        ok("уже пропатчено — повторная запись не требуется")
        if args.json:
            print(json.dumps({"path": str(path), "state": "patched", "version": insp.version},
                             ensure_ascii=False))
        return 0

    pids = is_binary_running(path)
    if pids:
        err("%s сейчас запущен (pid: %s). Закройте CLI и повторите." %
            (path, ", ".join(map(str, pids))))
        if not args.force:
            return 3
        err("--force: продолжаю на работающем процессе (не рекомендуется)")

    ensure_writable(path)

    data = bytearray(insp.data)
    changed = apply_gates(data, insp.relevant_gates)
    if not changed:
        err("нечего применять: нет гейтов в исходном состоянии")
        return 2

    new_digest = sha256_bytes(bytes(data))
    if args.dry_run:
        for st in changed:
            ok("DRY-RUN: %s @ 0x%x -> %s" % (st.gate.key, (st.offset or 0) + st.gate.fix_offset,
                                             st.gate.fix.hex()))
        ok("DRY-RUN: sha256 %s -> %s" % (insp.sha256[:16], new_digest[:16]))
        return 0

    backup, meta = create_backup(path, insp.data, insp)
    verify_backup_is_original(backup, meta)
    ok("резервная копия: %s" % backup)

    is_macho = insp.binfo.kind == "macho"
    app = _find_app_bundle(path) if is_macho else None
    no_resign = bool(getattr(args, "no_resign", False))
    allow_libval = bool(getattr(args, "macos_disable_library_validation", False))
    snap: Optional[Path] = None
    if is_macho and not no_resign and sys.platform == "darwin" and app:
        snap = snapshot_bundle_signature(app)

    mode = os.stat(path).st_mode & 0o7777
    try:
        write_target(path, bytes(data), mode)
        written = path.read_bytes()
        if sha256_bytes(written) != new_digest:
            raise PatchError("после записи хэш не совпал с ожидаемым")
        post = scan_binary(parse_binary(written), written)
        still = [s for s in post if s.state == "original"]
        if still:
            raise PatchError("после записи остались непропатченные гейты: %s" %
                             ", ".join(s.gate.key for s in still))
        if is_macho and not no_resign:
            macos_sign(path, app, allow_libval)
    except Exception as exc:  # noqa: BLE001 - нужен гарантированный откат
        err("ошибка записи/подписи: %s — восстанавливаю оригинал" % exc)
        try:
            write_target(path, insp.data, mode)
        except PatchError as wexc:
            err("восстановить оригинал не удалось: %s" % wexc)
            raise exc
        if snap is not None and app is not None:
            try:
                restore_bundle_signature(app)
            except PatchError as rexc:
                err("не удалось восстановить подпись бандла: %s" % rexc)
        raise

    for st in changed:
        ok("пропатчено: %-8s @ 0x%x  (%s)" %
           (st.gate.key, (st.offset or 0) + st.gate.fix_offset, st.gate.label))

    if is_macho and no_resign:
        warn("подпись не обновлена (--no-resign): macOS может не запустить файл")

    ok("новая версия файла: %s (%d байт)" % (path, len(data)))
    if args.json:
        print(json.dumps({
            "path": str(path), "state": "patched", "version": insp.version,
            "arch": insp.arch, "gates": [s.gate.key for s in changed],
            "sha256_before": insp.sha256, "sha256_after": new_digest,
            "backup": str(backup),
        }, ensure_ascii=False))
    return 0


def restore_one(path: Path, args: argparse.Namespace) -> int:
    try:
        insp = inspect(path)
    except PatchError as exc:
        # файл может быть уже заменён/удалён — всё равно пробуем откат
        err(str(exc))
        insp = None

    version = insp.version if insp else args.version
    explicit = Path(args.from_backup).expanduser() if args.from_backup else None
    try:
        backup, meta = find_backup(path, version, explicit)
        verify_backup_is_original(backup, meta)
    except PatchError as exc:
        err(str(exc))
        return 2

    target_digest = meta["sha256"]
    current = sha256_file(path) if path.is_file() else None
    if current == target_digest:
        ok("файл уже является оригиналом (%s)" % meta.get("version"))
        return 0

    if args.dry_run:
        ok("DRY-RUN: восстановил бы %s из %s (версия %s)" %
           (path, backup, meta.get("version")))
        return 0

    pids = is_binary_running(path)
    if pids:
        err("%s сейчас запущен (pid: %s). Закройте CLI и повторите." %
            (path, ", ".join(map(str, pids))))
        if not args.force:
            return 3

    ensure_writable(path)
    original = backup.read_bytes()
    mode = os.stat(path).st_mode & 0o7777 if path.exists() else 0o755
    write_target(path, original, mode)
    if sha256_file(path) != target_digest:
        err("после восстановления хэш не совпал")
        return 1

    try:
        is_macho = parse_binary(original).kind == "macho"
    except PatchError:
        is_macho = False
    app = _find_app_bundle(path) if is_macho else None
    if app is not None and sys.platform == "darwin":
        if not restore_bundle_signature(app):
            try:
                macos_sign(path, app, True)
            except PatchError as exc:
                warn("бандл не переподписан: %s" % exc)

    ok("восстановлен оригинал: %s (версия %s, sha256 %s)" %
       (path, meta.get("version"), target_digest[:16]))
    return 0


# --------------------------------------------------------------------------
# Вывод
# --------------------------------------------------------------------------

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, code: str) -> str:
    return "\033[%sm%s\033[0m" % (code, text) if _COLOR else text


def ok(msg: str) -> None:
    print("%s %s" % (_c("OK", "32"), msg))


def warn(msg: str) -> None:
    print("%s %s" % (_c("WARN", "33"), msg))


def err(msg: str) -> None:
    print("%s %s" % (_c("ERROR", "31"), msg), file=sys.stderr)


def print_target_header(insp: Inspection) -> None:
    print()
    print(_c(str(insp.path), "1"))
    print("  версия: %s   архитектура: %s   контейнер: %s   размер: %d байт" %
          (insp.version, insp.arch, insp.binfo.kind, len(insp.data)))
    print("  sha256: %s" % insp.sha256)


def cmd_status(args: argparse.Namespace) -> int:
    targets = resolve(args)
    if not targets:
        err("agy не найден. Укажите путь к файлу через --path.")
        return 2
    for path in targets:
        try:
            insp = inspect(path)
        except PatchError as exc:
            err("%s: %s" % (path, exc))
            continue
        print_target_header(insp)
        print("  состояние: %s" % {
            "original": _c("не пропатчен", "33"),
            "patched": _c("пропатчен", "32"),
            "partial": _c("частично", "33"),
            "broken": _c("повреждён", "31"),
            "unsupported": _c("сигнатуры не найдены", "31"),
        }.get(insp.overall, insp.overall))
        for st in insp.relevant_gates:
            mark = {
                "original": _c("original", "33"),
                "patched": _c("patched ", "32"),
                "absent": _c("absent  ", "90"),
                "mixed": _c("mixed   ", "31"),
                "ambiguous": _c("ambig   ", "31"),
            }[st.state]
            at = " @ 0x%x" % st.offset if st.offset is not None else ""
            print("    %s %-16s %s%s" % (mark, st.gate.key, st.gate.label, at))
        try:
            backup, meta = find_backup(path, insp.version)
            print("  резервная копия: %s (версия %s)" % (backup, meta.get("version")))
        except PatchError:
            print("  резервная копия: %s" % _c("нет", "33"))
        if not insp.arch.startswith("x64"):
            warn("для %s сигнатуры помечены как непроверенные" % insp.arch)
    print()
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    targets = resolve(args)
    bad = 0
    for path in targets:
        insp = inspect(path)
        print_target_header(insp)
        if insp.overall != "patched":
            err("состояние: %s" % insp.overall)
            bad += 1
        else:
            ok("все найденные гейты пропатчены")
    return 1 if bad else 0


def cmd_patch(args: argparse.Namespace) -> int:
    targets = resolve(args)
    if not targets:
        err("agy не найден. Укажите --path /путь/к/agy")
        return 2
    rc = 0
    for path in targets:
        try:
            rc = max(rc, patch_one(path, args))
        except PatchError as exc:
            err("%s: %s" % (path, exc))
            rc = max(rc, 2)
    return rc


def cmd_restore(args: argparse.Namespace) -> int:
    targets = resolve(args)
    if not targets:
        err("agy не найден. Укажите --path /путь/к/agy")
        return 2
    rc = 0
    for path in targets:
        rc = max(rc, restore_one(path, args))
    return rc


def cmd_backups(args: argparse.Namespace) -> int:
    manifests = sorted(backup_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not manifests:
        print("резервных копий нет")
        return 0
    for mpath in manifests:
        try:
            meta = json.loads(mpath.read_text("utf-8"))
        except (OSError, ValueError):
            continue
        print("%s  %-8s %-24s %s" % (
            meta.get("created_at", "?"), meta.get("version", "?"),
            meta.get("arch", "?"), meta.get("source", "?")))
        print("    backup: %s" % meta.get("backup"))
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    manifests = sorted(backup_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    keep = max(0, args.keep)
    removed = 0
    for mpath in manifests[keep:]:
        try:
            meta = json.loads(mpath.read_text("utf-8"))
            backup = Path(meta.get("backup", ""))
            if backup.is_file():
                backup.unlink()
                removed += 1
            mpath.unlink()
        except (OSError, ValueError):
            continue
    ok("удалено резервных копий: %d (оставлено %d)" % (removed, min(keep, len(manifests))))
    return 0


def cmd_gates(args: argparse.Namespace) -> int:
    for g in GATES:
        print("%-12s %-6s %s" % (g.key, g.arch, g.label))
        print("    fix @ +%d: %s" % (g.fix_offset, g.fix.hex()))
        print("    %s" % g.note)
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    targets = resolve(args)
    if not targets:
        err("agy не найден")
        return 2
    path = targets[0]
    cli_name = "agy.exe" if os.name == "nt" else "agy"
    if os.path.normcase(path.name) != cli_name:
        err("режим -p есть только у agy; для %s доступна команда status/verify" % path.name)
        return 2
    insp = inspect(path)
    print_target_header(insp)
    if insp.overall != "patched":
        warn("бинарник не пропатчен — тест может завершиться ошибкой eligibility")
    prompt = args.prompt or "Reply with exactly OK"
    cmd = [str(path), "-p", prompt]
    ok("запуск: %s" % " ".join(cmd))
    start = time.time()
    try:
        proc = subprocess.run(cmd, timeout=args.timeout, env={**os.environ, "NO_COLOR": "1"})
    except subprocess.TimeoutExpired:
        err("таймаут %s с" % args.timeout)
        return 1
    elapsed = time.time() - start
    print("---")
    print("код возврата: %d, время: %.1f с" % (proc.returncode, elapsed))
    return 0 if proc.returncode == 0 else proc.returncode


def _settings_path(args: argparse.Namespace) -> Path:
    explicit = getattr(args, "settings", None)
    if explicit:
        return Path(explicit).expanduser()
    return Path.home() / ".gemini" / "antigravity-cli" / "settings.json"


def list_models(path: Path, timeout: int = 60) -> List[Tuple[str, str]]:
    """Возвращает [(id, display_name)] из `agy models`."""
    try:
        proc = subprocess.run(
            [str(path), "models"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PatchError("не удалось получить список моделей: %s" % exc)
    text = proc.stdout.decode("utf-8", "replace")
    models: List[Tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Fetching"):
            continue
        parts = line.split("\t", 1)
        if len(parts) == 2:
            models.append((parts[0].strip(), parts[1].strip()))
    if not models:
        raise PatchError("список моделей пуст или формат вывода изменился")
    return models


def probe_model(path: Path, model_id: str, timeout: int) -> Tuple[bool, str]:
    """Один настоящий запрос к модели. Успех = код возврата 0."""
    try:
        proc = subprocess.run(
            [str(path), "--model", model_id, "-p", "Reply with exactly OK"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
        )
    except subprocess.TimeoutExpired:
        return False, "таймаут %d с" % timeout
    except OSError as exc:
        return False, str(exc)
    if proc.returncode == 0:
        return True, "OK"
    text = proc.stdout.decode("utf-8", "replace")
    m = re.search(r'"short_error":"(.*?)"', text)
    detail = m.group(1) if m else (text.strip().splitlines()[-1] if text.strip() else "")
    return False, detail[:180] or ("код %d" % proc.returncode)


# Порядок предпочтения при выборе модели по умолчанию: сначала не-Gemini,
# потому что Gemini-эндпоинт первым упирается в региональный отказ.
MODEL_PREFERENCE = ("claude-sonnet-4-6", "claude-opus-4-6-thinking", "gpt-oss-120b-medium")


def cmd_doctor(args: argparse.Namespace) -> int:
    targets = resolve(args)
    if not targets:
        err("agy не найден")
        return 2
    path = targets[0]
    print(_c(str(path), "1"))

    models = list_models(path)
    print("проверяю %d моделей реальным запросом…" % len(models))
    results: List[Tuple[str, str, bool, str]] = []
    for model_id, name in models:
        good, detail = probe_model(path, model_id, args.timeout)
        results.append((model_id, name, good, detail))
        print("  %s %-26s %-28s %s" % (
            _c("OK  ", "32") if good else _c("FAIL", "31"), model_id, name, "" if good else detail))
    working = [r for r in results if r[2]]
    if not working:
        err("ни одна модель не ответила: ограничение действует и на сервере.")
        err("локальный патч в этом случае не поможет — нужен регион, который Google поддерживает.")
        return 1

    chosen = None
    for preferred in MODEL_PREFERENCE:
        for r in working:
            if r[0] == preferred:
                chosen = r
                break
        if chosen:
            break
    if chosen is None:
        chosen = working[0]

    ok("работают: %s" % ", ".join(r[0] for r in working))
    print("модель по умолчанию: %s" % chosen[1])

    if not args.fix_default:
        print("\nчтобы записать её в настройки: %s --fix-default" % sys.argv[0])
        return 0

    settings_file = _settings_path(args)
    try:
        settings = json.loads(settings_file.read_text("utf-8")) if settings_file.is_file() else {}
    except (OSError, ValueError) as exc:
        err("не удалось прочитать %s: %s" % (settings_file, exc))
        return 2
    old = settings.get("model")
    if old == chosen[1]:
        ok("в настройках уже стоит %s" % old)
        return 0
    settings_file.parent.mkdir(parents=True, exist_ok=True)
    if settings_file.is_file():
        backup = settings_file.with_suffix(settings_file.suffix + ".bak")
        shutil.copy2(settings_file, backup)
        ok("резервная копия настроек: %s" % backup)
    settings["model"] = chosen[1]
    mode = (settings_file.stat().st_mode & 0o777) if settings_file.exists() else 0o600
    atomic_write(settings_file, (json.dumps(settings, ensure_ascii=False, indent=2) + "\n").encode("utf-8"), mode)
    ok("модель по умолчанию: %s → %s" % (old or "не задана", chosen[1]))
    return 0


def resolve(args: argparse.Namespace) -> List[Path]:
    if getattr(args, "path", None):
        return [Path(p).expanduser() for p in args.path]
    return default_targets(getattr(args, "all", False), getattr(args, "app", False))


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

class _Lock:
    def __init__(self) -> None:
        self.path = state_dir() / ".lock"
        self.fh = None

    def __enter__(self) -> "_Lock":
        self.fh = open(self.path, "a+b")
        try:
            if os.name == "nt":
                self.fh.seek(0, os.SEEK_END)
                if self.fh.tell() == 0:
                    self.fh.write(b"\0")
                    self.fh.flush()
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            err("другой экземпляр %s уже работает" % TOOL)
            raise SystemExit(3)
        return self

    def __exit__(self, *exc: object) -> None:
        if self.fh:
            if os.name == "nt":
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            self.fh.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL,
        description="Локальный патч регионального гейта Antigravity CLI (agy/agy.exe).",
    )
    p.add_argument("--path", action="append", metavar="FILE",
                   help="путь к agy (можно повторять); по умолчанию ищется в PATH")
    p.add_argument("--all", action="store_true",
                   help="включить также ~/.gemini/bin/agy (бэкенд IDE)")
    p.add_argument("--app", action="store_true",
                   help="включить бэкенды приложений Antigravity App/IDE")
    p.add_argument("--json", action="store_true", help="машинный вывод для patch")
    p.add_argument("--dry-run", action="store_true", help="ничего не записывать")
    p.add_argument("--force", action="store_true", help="игнорировать запущенный процесс")
    p.add_argument("--no-resign", action="store_true",
                   help="не переподписывать Mach-O (macOS) после патча")
    p.add_argument("--macos-disable-library-validation", action="store_true",
                   help="устарело: бандл подписывается без Hardened Runtime, "
                        "флаг принимается для совместимости")
    p.add_argument("--version", action="version", version="%s %s" % (TOOL, TOOL_VERSION))

    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="показать состояние agy и найденных сигнатур")
    sub.add_parser("verify", help="проверить, что патч на месте")
    sub.add_parser("patch", help="применить патч")
    r = sub.add_parser("restore", help="восстановить оригинал из резервной копии")
    r.add_argument("--from", dest="from_backup", metavar="FILE", help="конкретная резервная копия")
    r.add_argument("--version", dest="version", help="версия резервной копии")
    sub.add_parser("backups", help="список резервных копий")
    pr = sub.add_parser("prune", help="удалить старые резервные копии")
    pr.add_argument("--keep", type=int, default=2, help="сколько последних оставить (по умолчанию 2)")
    sub.add_parser("gates", help="показать известные сигнатуры")
    t = sub.add_parser("test", help="реальный запрос к модели через agy -p")
    t.add_argument("--prompt", help="текст запроса")
    t.add_argument("--timeout", type=int, default=180, help="таймаут, секунды")
    d = sub.add_parser("doctor", help="проверить модели и поставить рабочую по умолчанию")
    d.add_argument("--timeout", type=int, default=120, help="таймаут одного запроса, секунды")
    d.add_argument("--fix-default", action="store_true",
                   help="записать рабочую модель в settings.json (с резервной копией)")
    d.add_argument("--settings", metavar="FILE", help="путь к settings.json")

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "status": cmd_status,
        "verify": cmd_verify,
        "patch": cmd_patch,
        "restore": cmd_restore,
        "backups": cmd_backups,
        "prune": cmd_prune,
        "gates": cmd_gates,
        "test": cmd_test,
        "doctor": cmd_doctor,
    }
    handler = handlers[args.command]
    if args.command in ("patch", "restore"):
        with _Lock():
            return handler(args)
    return handler(args)


def cli() -> int:
    """Точка входа для console_scripts и прямого запуска."""
    try:
        return main()
    except PatchError as exc:
        err(str(exc))
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(cli())
