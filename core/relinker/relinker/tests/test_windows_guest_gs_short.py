from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from test_windows_guest_gs_integration import executable_relocation, guest_relocation
from test_windows_tls_protected_entries import make_image, pe_bytes_at
from test_guest_intel_trampolines import main_fixture


SHORT = bytes.fromhex("65 8b 02 b8 90 90 90 90 c3")


def main():
    relinker = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="anyps5-gs-short-") as directory:
        work = Path(directory)
        number = 0

        def convert(image, module=None):
            nonlocal number
            case = work / str(number)
            number += 1
            case.mkdir()
            if module is not None:
                (case / "prx").mkdir()
                (case / "prx" / "consumer.prx").write_bytes(module)
            source = case / "input.elf"
            output = case / "output.exe"
            source.write_bytes(image)
            run = subprocess.run([str(relinker), "--windows", *(["--skip-sce-module"] if module is None else []), str(source), str(output)], capture_output=True, text=True, timeout=10)
            return run, output

        for root in ("relative", "symbol", "lea", "initializer"):
            image = make_image(root)
            image[0x210:0x210 + len(SHORT)] = SHORT
            run, output = convert(image)
            assert run.returncode == 2 and "GS trap would overwrite an executable entry point" in run.stderr and not output.exists(), (root, run)
        for delta in range(1, 6):
            image = make_image("relative")
            image[0x210:0x210 + len(SHORT)] = SHORT
            struct.pack_into("<q", image, 0x728, 0x210 + delta)
            run, output = convert(image)
            if delta < 5:
                assert run.returncode == 2 and "GS trap would overwrite an executable entry point" in run.stderr and not output.exists(), (delta, run)
            else:
                assert run.returncode == 0, run
                assert pe_bytes_at(output.read_bytes(), 0x10215, 4) == SHORT[5:], run
        for delta in range(1, 6):
            image = make_image()
            image[0x210:0x210 + len(SHORT)] = SHORT
            image[0x200:0x204] = bytes((0x75, 0x10 + delta - 2, 0xeb, 0x10 - 4))
            run, output = convert(image)
            if delta < 5:
                assert run.returncode == 2 and "Branch enters a guest GS instruction" in run.stderr and not output.exists(), (delta, run)
            else:
                assert run.returncode == 0, run
                assert pe_bytes_at(output.read_bytes(), 0x10215, 4) == SHORT[5:]
        for kind in (1, 6, 8, 17, 18):
            for target in (0x213, 0x219):
                image = executable_relocation(kind, target)
                image[0x210:0x21e] = bytes.fromhex("65 8b 02 48 b8 00 00 00 00 00 00 00 00 c3")
                run, output = convert(image)
                assert run.returncode == 2 and "Relocation overlaps a Windows guest GS instruction" in run.stderr and not output.exists(), (kind, target, run)
        for kind in (1, 6, 8, 16, 17, 18):
            image = guest_relocation(kind)
            image[0x400:0x40e] = bytes.fromhex("65 8b 02 48 b8 00 00 00 00 00 00 00 00 c3")
            struct.pack_into("<Q", image, 0x900, 0x1009)
            run, output = convert(main_fixture(), image)
            assert run.returncode == 2 and "Relocation overlaps a Windows guest GS instruction" in run.stderr and not output.exists(), (kind, run)
    print("Short guest GS entry and relocation safety passed")


if __name__ == "__main__":
    main()
