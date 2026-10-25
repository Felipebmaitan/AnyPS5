from pathlib import Path
import os
import struct
import subprocess
import sys
import tempfile

from test_sce_module_code_extent import sce_module
from test_guest_symbol_names import importing_executable, dynamic_tags
from test_guest_module_args import args_module
from test_sce_code_extent import fixture as plt_fixture
from test_jmprel_table_bounds import fixture as no_tail_fixture
from test_tls_function_coverage import pe_bytes_at
from test_macos_output import MachO

TAIL = 0x1030
TLS = bytes.fromhex("64 48 8b 04 25 00 00 00 00 8b 40 f8 c3")
SYSCALL = bytes.fromhex("0f 05 c3")
LOOKALIKE = bytes.fromhex("64 2d 65 6c 66 2e 0f 05 0f 78")


def fixture(root, body=TLS, relocated=False, unwind=False):
    image = sce_module()
    image[0x400:0x480] = b"\xcc" * 0x80
    image[0x400:0x410] = bytes.fromhex("b8 2a 00 00 00 c3") + b"\x90" * 10
    image[0x420:0x420 + len(LOOKALIKE)] = LOOKALIKE
    image[0x430:0x430 + len(body)] = body
    struct.pack_into("<H", image, 56, 6)
    struct.pack_into("<IIQQQQQQ", image, 344, 7, 4, 0x900, 0x2300, 0x2300, 8, 8, 8)
    struct.pack_into("<Q", image, 0x900, 42)
    tags = [(0x61000035, 0), (0x61000037, 16), (0x61000039, 0x20),
            (0x6100003B, 24), (0x6100003F, 24)]
    if root == "entry":
        struct.pack_into("<Q", image, 24, TAIL)
    elif root in ("init", "fini"):
        tags.append((12 if root == "init" else 13, TAIL))
    elif root in ("init-array", "fini-array"):
        tags += [(25 if root == "init-array" else 26, 0x2200), (27 if root == "init-array" else 28, 8)]
        struct.pack_into("<Q", image, 0x800, 0 if relocated else TAIL)
    elif root == "symbol":
        tags[-1] = (0x6100003F, 48)
        image[0xA00:0xA10] = b"\0tail\0" + bytes(10)
        struct.pack_into("<IBBHQQ", image, 0xA38, 1, 0x12, 0, 1, TAIL, len(body))
    elif root in ("branch", "indirect"):
        code = b"\xe9" + struct.pack("<i", TAIL - 0x1005) if root == "branch" else b"\xff\x25" + struct.pack("<i", 0x2200 - 0x1006)
        image[0x400:0x400 + len(code)] = code
    elif root in ("fallthrough", "call-continuation", "conditional"):
        image[0x400:0x410] = b"\x90" * 16
        image[0x410:0x410 + len(body)] = body
        image[0x450] = 0xC3
        if root == "call-continuation":
            image[0x40B:0x410] = b"\xe8" + struct.pack("<i", 0x1050 - 0x1010)
        if root == "conditional":
            image[0x40E:0x410] = bytes.fromhex("74 40")
    elif root == "data-pointer":
        image[0x400:0x408] = b"\x48\x8d\x05" + struct.pack("<i", TAIL - 0x1007) + b"\xc3"
    elif root != "none":
        raise ValueError(root)
    if relocated or root == "indirect":
        tags += [(0x6100002F, 0x80), (0x61000031, 24), (0x61000033, 24)]
        struct.pack_into("<QQq", image, 0xA80, 0x2200, 8, TAIL)
    tags.append((0, 0))
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x600 + index * 16, *tag)
    struct.pack_into("<QQ", image, 176 + 32, len(tags) * 16, len(tags) * 16)
    if unwind:
        frame, cie = 0x10A0, 0x10A0
        fde = frame + 20
        struct.pack_into("<IIiiB3x", image, 0x400 + fde - 0x1000, 16, fde + 4 - cie, 0x1000 - (fde + 8), 16, 0)
        fde += 20
        struct.pack_into("<IIiiB3x", image, 0x400 + fde - 0x1000, 16, fde + 4 - cie, TAIL - (fde + 8), len(body), 0)
        struct.pack_into("<I", image, 0x400 + fde - 0x1000 + 20, 0)
        struct.pack_into("<I", image, 0x488, 2)
        struct.pack_into("<ii", image, 0x494, TAIL - 0x1080, fde - 0x1080)
        struct.pack_into("<QQ", image, 288 + 32, 28, 28)
    return image


def output_bytes(image, system, address, size):
    if system == "windows":
        return pe_bytes_at(image, 0x10000 + address - 0x1000, size)
    if system == "macos":
        macho = MachO(image)
        base = next(s["vmaddr"] for s in macho.segments if s["name"] == "__ELF0") - 0x1000
        for segment in macho.segments:
            offset = base + address - segment["vmaddr"]
            if 0 <= offset and offset + size <= segment["filesize"]:
                start = segment["fileoff"] + offset
                return image[start:start + size]
        raise AssertionError(hex(address))
    offset, count = struct.unpack_from("<Q", image, 32)[0], struct.unpack_from("<H", image, 56)[0]
    base = next(struct.unpack_from("<Q", image, offset + index * 56 + 16)[0] for index in range(count) if struct.unpack_from("<I", image, offset + index * 56)[0] == 1) - 0x1000
    address += base
    for index in range(count):
        kind, _, raw, virtual, _, length = struct.unpack_from("<IIQQQQ", image, offset + index * 56)
        if kind == 1 and virtual <= address and address + size <= virtual + length:
            return image[raw + address - virtual:raw + address - virtual + size]
    raise AssertionError(hex(address))


def convert(relinker, work, name, image, system, error=None, module=False, flags=()):
    case = work / name
    case.mkdir()
    source, output = case / "input.elf", case / "output.exe"
    if module:
        modules = case / "sce_module"
        modules.mkdir()
        (modules / "tail.prx").write_bytes(image)
        source.write_bytes(importing_executable([]))
    else:
        source.write_bytes(image)
    command = [str(relinker), *([] if module else ["--skip-sce-module"]), *([] if system == "linux" else ["--" + system]), *flags, str(source), str(output)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    if error:
        assert result.returncode == 2 and error in result.stderr and not output.exists(), (name, result.returncode, result.stdout, result.stderr)
        return
    assert result.returncode == 0, (name, result.stdout, result.stderr)
    converted = case / "app0/sce_module/tail.prx.guest.prx" if module else output
    return converted


def imported_array():
    image = args_module()
    tags = list(dynamic_tags(image).items()) + [(25, 0x2900), (27, 8), (0, 0)]
    tags = [(tag, 48 if tag == 8 else value) for tag, value in tags]
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x2000 + index * 16, *tag)
    struct.pack_into("<QQ", image, 120 + 32, len(tags) * 16, len(tags) * 16)
    struct.pack_into("<QQq", image, 0x2718, 0x2900, (1 << 32) | 1, 0)
    struct.pack_into("<Q", image, 0x2900, 0xDEADBEEF)
    return image


def padded_call(kind, body, padding=0):
    image = fixture("entry", relocated=kind == "rip")
    image[0x430:0x480] = b"\xcc" * 0x50
    image[0x400:0x408] = b"\x48\x8d\x05" + struct.pack("<i", 0x2208 - 0x1007) + b"\xc3"
    if kind == "direct":
        code = b"\x90" * 3 + b"\xe8" + struct.pack("<i", 0x1000 - 0x1038)
    elif kind == "rip":
        code = b"\xff\x15" + struct.pack("<i", 0x2200 - 0x1036)
        struct.pack_into("<q", image, 0xA90, 0x1000)
    else:
        code = b"\x4c\x8d\x1d" + struct.pack("<i", 0x1000 - 0x1037) + bytes.fromhex("41 ff d3")
    image[0x430:0x430 + len(code)] = code
    image[0x430 + len(code):0x440] = bytes([padding]) * (16 - len(code))
    image[0x440:0x440 + len(body)] = body
    return image


def extra_segment(image, address, body):
    headers = bytes(image[64:400])
    image.extend(bytes(0x1000 - len(image)))
    image[0xD00:0xD00 + len(headers)] = headers
    struct.pack_into("<Q", image, 32, 0xD00)
    struct.pack_into("<H", image, 56, 7)
    struct.pack_into("<IIQQQQQQ", image, 0xD00 + 6 * 56, 1, 5, 0xC00, address, address, len(body), len(body), 0x100)
    image[0xC00:0xC00 + len(body)] = body
    return image


def adjacent_segment(kind):
    image = fixture("entry")
    struct.pack_into("<Q", image, 24, 0x10F0)
    image[0x4F0:0x500] = b"\x90" * 16
    if kind == "call":
        image[0x4FB:0x500] = b"\xe8" + struct.pack("<i", 0x1050 - 0x1100)
        image[0x450] = 0xC3
    elif kind == "jump":
        image[0x4F0:0x4F5] = b"\xe9" + struct.pack("<i", 0x1100 - 0x10F5)
    elif kind == "zeros":
        image[0x4F0:0x4F8] = b"\x48\x8d\x05" + struct.pack("<i", 0x2208 - 0x10F7) + b"\x90"
        image[0x4F8:0x500] = bytes(8)
    return extra_segment(image, 0x1100, TLS)


def flow_roundtrip(padding, body):
    image = fixture("entry")
    image[0x400] = 0xC3
    image[0x430:0x480] = b"\xcc" * 0x50
    image[0x430:0x435] = b"\xe9" + struct.pack("<i", 0x3000 - 0x1035)
    image[0x440:0x440 + len(body)] = body
    helper = b"\x48\x8d\x05" + struct.pack("<i", 0x2208 - 0x3007)
    helper += b"\xe8" + struct.pack("<i", 0x1000 - 0x300C)
    helper += bytes([padding]) * 4
    helper += b"\xe9" + struct.pack("<i", 0x1040 - 0x3015)
    return extra_segment(image, 0x3000, helper)


def prefix_zeros(body, padding):
    image = fixture("fallthrough", body)
    image[0x400:0x408] = b"\x48\x8d\x05" + struct.pack("<i", 0x2208 - 0x1007) + b"\x90"
    image[0x408:0x410] = bytes([padding]) * 8
    return image


def lea_observer(function):
    image = fixture("symbol")
    struct.pack_into("<Q", image, 0xA40, 0x1050)
    image[0xA3C] = 0x12 if function else 0x11
    image[0x400:0x410] = b"\x8d\x05" + struct.pack("<i", 0x1054 - 0x1006) + b"\xc3" + b"\x90" * 9
    struct.pack_into("<Q", image, 24, TAIL)
    image[0x430:0x440] = b"\xe8" + struct.pack("<i", 0x1000 - 0x1035) + bytes.fromhex("0f b6 00 c3") + b"\xcc" * 7
    image[0x450:0x450 + len(TLS)] = TLS
    return image


def null_symbol(root, indexed, stale, body=TLS, shifted=False):
    image = fixture(root, body, relocated=True)
    struct.pack_into("<Q", image, 0xA88, ((1 if indexed else 0) << 32) | 1)
    if indexed:
        struct.pack_into("<Q", image, 0x648, 48)
    struct.pack_into("<Q", image, 0x800, stale)
    if shifted:
        delta = 0x2F000
        struct.pack_into("<Q", image, 24, 0x1000 + delta)
        for header in range(6):
            at = 64 + header * 56
            if struct.unpack_from("<I", image, at)[0] == 0x61000000:
                continue
            for field in (16, 24):
                value = struct.unpack_from("<Q", image, at + field)[0]
                struct.pack_into("<Q", image, at + field, value + delta)
        for at in (0xA80, 0xA90):
            struct.pack_into("<Q", image, at, struct.unpack_from("<Q", image, at)[0] + delta)
        for at in range(0x600, 0x6A0, 16):
            if struct.unpack_from("<Q", image, at)[0] in (25, 26):
                struct.pack_into("<Q", image, at + 8, 0x2200 + delta)
    return image


def main():
    relinker = Path(sys.argv[1]).resolve()
    systems = [sys.argv[2]] if len(sys.argv) > 2 else ["linux", "windows", "macos"]
    with tempfile.TemporaryDirectory(prefix="anyps5-referenced-code-") as directory:
        work = Path(directory)
        for root in (("entry", "branch", "indirect") if "windows" in systems else ()):
            converted = convert(relinker, work, "unwind-control-" + root, fixture(root, unwind=True), "windows")
            assert output_bytes(converted.read_bytes(), "windows", TAIL, 1) == b"\xe9"
            if os.name == "nt":
                run = subprocess.run([str(converted)], capture_output=True, timeout=10)
                assert run.returncode == 42, (root, run.returncode, run.stderr)
        if "linux" in systems:
            image = no_tail_fixture(linux=True)
            struct.pack_into("<qQqQ", image, 0x4D0, 11, 24, 0, 0)
            struct.pack_into("<QQ", image, 120 + 32, 240, 240)
            convert(relinker, work, "no-tail-identical-tags", image, "linux")
        for system in systems:
            converted = convert(relinker, work, system + "-lea-observer-data", lea_observer(False), system)
            assert output_bytes(converted.read_bytes(), system, 0x1054, 1) == b"\x25"
            if os.name == "nt" and system == "windows":
                run = subprocess.run([str(converted)], capture_output=True, timeout=10)
                assert run.returncode == 37, (run.returncode, run.stderr)
            convert(relinker, work, system + "-lea-observer-overlap", lea_observer(True), system,
                    "Code analysis: reference enters an analyzed instruction")
            convert(relinker, work, system + "-external-array", imported_array(), system, module=True)
            if system != "linux":
                for plt in (0x180, 0x210):
                    image, _ = plt_fixture(plt_at=plt, tls=True)
                    image[0x280:0x280 + len(TLS)] = TLS
                    struct.pack_into("<qQqQ", image, 0x4D0, 12, 0x280, 0, 0)
                    struct.pack_into("<QQ", image, 120 + 32, 240, 240)
                    converted = convert(relinker, work, f"{system}-plt-{plt:x}", image, system)
                    assert TLS not in converted.read_bytes()
            if system == "linux":
                for root in ("entry", "none"):
                    image = fixture(root)
                    struct.pack_into("<qQqQ", image, 0x650, 0x6100003B, 24, 0, 0)
                    struct.pack_into("<QQ", image, 176 + 32, 112, 112)
                    convert(relinker, work, "tail-identical-tags-" + root, image, system)
            for indexed in (False, True):
                for stale in (0, 0xDEADBEEF):
                    for root in ("init-array", "indirect"):
                        name = f"{system}-null-{indexed}-{stale}-{root}"
                        convert(relinker, work, name + "-syscall", null_symbol(root, indexed, stale, SYSCALL), system,
                                "Forbidden syscall instruction at code offset 0x1030")
                        converted = convert(relinker, work, name, null_symbol(root, indexed, stale), system)
                        actual = output_bytes(converted.read_bytes(), system, TAIL, len(TLS))
                        assert (actual == TLS if system == "linux" else actual[:1] == b"\xe9"), name
                        if system != "linux":
                            assert output_bytes(converted.read_bytes(), system, 0x2200, 8) == struct.pack("<Q", TAIL), name
                        if os.name == "nt" and system == "windows":
                            native = convert(relinker, work, name + "-native", null_symbol(root, indexed, stale, shifted=True), system,
                                             flags=("--windows-fixed-base", "0x30000"))
                            run = subprocess.run([str(native)], capture_output=True, timeout=10)
                            assert run.returncode == 42, (name, run.returncode, run.stderr)
            for module in (False, True):
                for padding in (0, 0x90):
                    name = f"{system}-{module}-prefix-zeros-{padding}"
                    convert(relinker, work, name + "-syscall", prefix_zeros(SYSCALL, padding), system,
                            "Forbidden syscall instruction at code offset 0x1010", module)
                    converted = convert(relinker, work, name, prefix_zeros(TLS, padding), system, module=module)
                    actual = output_bytes(converted.read_bytes(), system, 0x1010, len(TLS))
                    assert (actual == TLS if system == "linux" else actual[:1] == b"\xe9"), name
                    if os.name == "nt" and system == "windows" and not module:
                        run = subprocess.run([str(converted)], capture_output=True, timeout=10)
                        assert run.returncode == 42, (name, run.returncode, run.stderr)
                for padding in (0, 0x90):
                    name = f"{system}-{module}-roundtrip-{padding}"
                    convert(relinker, work, name + "-syscall", flow_roundtrip(padding, SYSCALL), system,
                            "Forbidden syscall instruction at code offset 0x1040", module)
                    converted = convert(relinker, work, name, flow_roundtrip(padding, TLS), system, module=module)
                    actual = output_bytes(converted.read_bytes(), system, 0x1040, len(TLS))
                    assert (actual == TLS if system == "linux" else actual[:1] == b"\xe9"), name
                    if os.name == "nt" and system == "windows" and not module:
                        run = subprocess.run([str(converted)], capture_output=True, timeout=10)
                        assert run.returncode == 42, (name, run.returncode, run.stderr)
                for kind in ("direct", "rip", "register"):
                    for padding in (0, 0x90):
                        name = f"{system}-{module}-padded-{kind}-{padding}"
                        convert(relinker, work, name + "-syscall", padded_call(kind, SYSCALL, padding), system,
                                "Forbidden syscall instruction at code offset 0x1040", module)
                        converted = convert(relinker, work, name, padded_call(kind, TLS, padding), system, module=module)
                        actual = output_bytes(converted.read_bytes(), system, 0x1040, len(TLS))
                        assert (actual == TLS if system == "linux" else actual[:1] == b"\xe9"), name
                        if os.name == "nt" and system == "windows" and not module:
                            run = subprocess.run([str(converted)], capture_output=True, timeout=10)
                            assert run.returncode == 42, (name, run.returncode, run.stderr)
                for kind in ("fallthrough", "call", "jump", "zeros"):
                    name = f"{system}-{module}-adjacent-{kind}"
                    converted = convert(relinker, work, name, adjacent_segment(kind), system, module=module)
                    actual = output_bytes(converted.read_bytes(), system, 0x1100, len(TLS))
                    assert (actual == TLS if system == "linux" else actual[:1] == b"\xe9"), name
                    if os.name == "nt" and system == "windows" and not module:
                        run = subprocess.run([str(converted)], capture_output=True, timeout=10)
                        assert run.returncode == 42, (name, run.returncode, run.stderr)
                for root in ("fallthrough", "call-continuation", "conditional"):
                    convert(relinker, work, f"{system}-{module}-{root}-syscall", fixture(root, SYSCALL), system,
                            "Forbidden syscall instruction at code offset 0x1010", module)
                    converted = convert(relinker, work, f"{system}-{module}-{root}", fixture(root), system, module=module)
                    data = converted.read_bytes()
                    actual = output_bytes(data, system, 0x1010, len(TLS))
                    assert (actual == TLS if system == "linux" else actual[:1] == b"\xe9"), (root, actual.hex())
                    assert output_bytes(data, system, TAIL, len(TLS)) == TLS
                    if os.name == "nt" and system == "windows" and not module and root != "conditional":
                        run = subprocess.run([str(converted)], capture_output=True, timeout=10)
                        assert run.returncode == 42, (root, run.returncode, run.stderr)
                for root in ("entry", "init", "fini", "init-array", "fini-array", "symbol", "branch", "indirect"):
                    name = f"{system}-{module}-{root}"
                    convert(relinker, work, name + "-syscall", fixture(root, SYSCALL, relocated=root.endswith("array")), system,
                            "Forbidden syscall instruction at code offset 0x1030", module)
                    converted = convert(relinker, work, name, fixture(root, relocated=root.endswith("array")), system, module=module)
                    data = converted.read_bytes()
                    assert output_bytes(data, system, 0x1020, len(LOOKALIKE)) == LOOKALIKE, name
                    actual = output_bytes(data, system, TAIL, len(TLS))
                    assert (actual == TLS if system == "linux" else actual[:1] == b"\xe9"), (name, actual.hex())
                    if os.name == "nt" and system == "windows" and not module and root in ("entry", "branch", "indirect"):
                        run = subprocess.run([str(converted)], capture_output=True, timeout=10)
                        assert run.returncode == 42, (name, run.returncode, run.stderr)
                for root in ("init-array", "fini-array", "symbol"):
                    image = fixture(root)
                    if root == "symbol":
                        struct.pack_into("<Q", image, 0xA48, 0)
                    if module and root.endswith("array"):
                        convert(relinker, work, f"{system}-{module}-{root}-raw", image, system,
                                "Unrelocated guest lifecycle pointer", module=True)
                        continue
                    converted = convert(relinker, work, f"{system}-{module}-{root}-raw", image, system, module=module)
                    actual = output_bytes(converted.read_bytes(), system, TAIL, len(TLS))
                    assert (actual == TLS if system == "linux" else actual[:1] == b"\xe9"), root
                for reference in ("relocation", "lea", "lea32", "lea16", "lea-address32", "lea16-high"):
                    for interior in (1, 4, 8):
                        image = fixture("entry", relocated=reference == "relocation")
                        if reference == "relocation":
                            struct.pack_into("<q", image, 0xA90, TAIL + interior)
                        else:
                            prefix = {"lea": b"\x48", "lea32": b"", "lea16": b"\x66", "lea-address32": b"\x67\x48", "lea16-high": b"\x66"}[reference]
                            code = prefix + b"\x8d\x05" + struct.pack("<i", TAIL + interior - (0x1006 + len(prefix))) + b"\xc3"
                            image[0x400:0x400 + len(code)] = code
                            if reference == "lea16-high":
                                struct.pack_into("<Q", image, 24, TAIL + 0x10000)
                                for header in range(6):
                                    at = 64 + header * 56
                                    if struct.unpack_from("<I", image, at)[0] == 0x61000000:
                                        continue
                                    for field in (16, 24):
                                        value = struct.unpack_from("<Q", image, at + field)[0]
                                        struct.pack_into("<Q", image, at + field, value + 0x10000)
                        convert(relinker, work, f"{system}-{module}-{reference}-interior-{interior}", image, system,
                                "Code analysis: reference enters an analyzed instruction", module)
                for opcode in ("0f34", "cd80", "0f07"):
                    convert(relinker, work, f"{system}-{module}-forbidden-{opcode}", fixture("entry", bytes.fromhex(opcode) + b"\xc3"), system,
                            "Forbidden syscall instruction at code offset 0x1030", module)
                truncated = fixture("entry")
                struct.pack_into("<Q", truncated, 24, 0x10FF)
                truncated[0x4FF] = 0x0F
                convert(relinker, work, f"{system}-{module}-truncated", truncated, system,
                        "Instruction truncated after two-byte opcode escape", module)
                inline = bytes.fromhex("49 63 d6 4c 63 d1 4d 63 c0 b8 dd 01 00 00 48 89 de 0f 05 48 89 c1 0f 93 c2 48 f7 d8 84 d2 48 0f 45 c1 48 85 c0")
                converted = convert(relinker, work, f"{system}-{module}-inline-trap", fixture("entry", inline + TLS), system,
                                    module=module, flags=("--trap-sdk-syscall-stubs",))
                data = converted.read_bytes()
                assert output_bytes(data, system, TAIL + 17, 2) == bytes.fromhex("0f 0b")
                actual = output_bytes(data, system, TAIL + len(inline), len(TLS))
                assert (actual == TLS if system == "linux" else actual[:1] == b"\xe9"), (system, module, actual.hex())
                converted = convert(relinker, work, f"{system}-{module}-intentional-trap", fixture("entry", bytes.fromhex("0f 0b") + TLS), system, module=module)
                assert output_bytes(converted.read_bytes(), system, TAIL + 2, len(TLS)) == TLS
                sdk = bytes.fromhex("48 c7 c0 01 00 00 00 49 89 ca 0f 05 c3")
                trapped = convert(relinker, work, f"{system}-{module}-trap", fixture("entry", sdk), system,
                                  module=module, flags=("--trap-sdk-syscall-stubs",))
                assert output_bytes(trapped.read_bytes(), system, TAIL + 10, 3) == bytes.fromhex("0f 0b c3")
                overlap = fixture("entry", bytes.fromhex("b8 0f 05 c3 00 c3"))
                struct.pack_into("<qQqQ", overlap, 0x650, 12, TAIL + 1, 0, 0)
                struct.pack_into("<QQ", overlap, 176 + 32, 112, 112)
                convert(relinker, work, f"{system}-{module}-overlap", overlap, system,
                        "Code analysis: overlapping instruction boundaries", module)
                for root in ("none", "data-pointer"):
                    converted = convert(relinker, work, f"{system}-{module}-{root}", fixture(root, LOOKALIKE, relocated=True), system, module=module)
                    assert output_bytes(converted.read_bytes(), system, TAIL, len(LOOKALIKE)) == LOOKALIKE
    print("Referenced SCE code tests passed; native Windows execution " + ("passed" if os.name == "nt" and "windows" in systems else "not run"))


if __name__ == "__main__":
    main()
