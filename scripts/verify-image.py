#!/usr/bin/env python3
"""Verify non-root Distroless runtime: only /server executable, no ELF interpreter."""
import json
import struct
import subprocess
import tarfile
import tempfile

IMAGE = "obsidian-sync:local"
info = json.loads(subprocess.check_output(["docker", "image", "inspect", IMAGE]))[0]
assert info["Config"]["User"] == "65532:65532", "Runtime must explicitly be non-root"
assert info["Config"]["Entrypoint"] == ["/server"]
container = subprocess.check_output(["docker", "create", IMAGE], text=True).strip()
try:
    with tempfile.TemporaryFile() as archive:
        subprocess.run(["docker", "export", container], stdout=archive, check=True)
        archive.seek(0)
        with tarfile.open(fileobj=archive) as filesystem:
            # Docker injects these non-image files; some VM exporters mark them executable.
            injected = {".dockerenv", "dev/console", "etc/hostname", "etc/hosts", "etc/resolv.conf"}
            executables = []
            for member in filesystem:
                name = member.name.removeprefix("./").lstrip("/")
                if member.isfile() and member.mode & 0o111:
                    if name in injected:
                        prefix = filesystem.extractfile(member).read(4)
                        assert not prefix.startswith((b"\\x7fELF", b"#!")), "Executable in Docker-injected file"
                    else:
                        executables.append(name)
            assert sorted(executables) == ["server"], f"Unexpected executables: {executables}"
            names = {m.name.removeprefix("./").lstrip("/") for m in filesystem.getmembers()}
            assert not names.intersection({"bin/sh", "bin/bash", "sbin/apk", "usr/bin/apt", "usr/bin/env"})
            binary = filesystem.extractfile("server").read()
            assert binary[:5] == b"\x7fELF\x02", "Expected 64-bit ELF"
            endian = "<" if binary[5] == 1 else ">"
            offset = struct.unpack_from(endian + "Q", binary, 32)[0]
            size, count = struct.unpack_from(endian + "HH", binary, 54)
            assert offset + size * count <= len(binary) and size >= 4
            for index in range(count):
                kind = struct.unpack_from(endian + "I", binary, offset + size * index)[0]
                assert kind != 3, "Dynamic ELF interpreter found"
    print(f"Verified {info['Id']}: non-root, only /server executable, statically linked, no shell/package manager")
finally:
    subprocess.run(["docker", "rm", container], check=True, stdout=subprocess.DEVNULL)
