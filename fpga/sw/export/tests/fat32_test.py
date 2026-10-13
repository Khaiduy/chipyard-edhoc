#!/usr/bin/env python3
"""Host test for common/src/fat32.c (make fat32-host-test).

Builds an SD image laid out like the board's card (MBR, raw boot partition
at LBA 2048, FAT32 behind it), lets pyfatfs place a fragmented SEND.BIN and
an old RECV.BIN, runs build/fat32_host, then checks the result with pyfatfs
and fsck.fat. Needs dosfstools and `pip install pyfatfs`.
"""
import os, struct, subprocess, sys
from pyfatfs.PyFatFS import PyFatFS

HOST = sys.argv[1] if len(sys.argv) > 1 else "build/fat32_host"
IMG = "build/fat32_test.img"
P1, P1_LEN = 2048, 32768          # raw boot partition, as sd_boot.sh expects
P2 = P1 + P1_LEN                  # FAT32 partition
P2_LEN = 140000                   # 1-sector clusters: > 65525, still FAT32


def mbr_entry(ptype, start, count):
    return struct.pack("<B3sB3sII", 0, b"\0\0\0", ptype, b"\0\0\0", start, count)


def make_image(files, delete=()):
    with open(IMG, "wb") as f:
        f.truncate((P2 + P2_LEN) * 512)
        f.seek(446)
        f.write(mbr_entry(0xDA, P1, P1_LEN) + mbr_entry(0x0C, P2, P2_LEN))
        f.seek(510)
        f.write(b"\x55\xaa")
    subprocess.run(["mkfs.vfat", "-F", "32", "-s", "1", "--offset", str(P2),
                    IMG, str(P2_LEN // 2)], check=True, capture_output=True)
    fs = PyFatFS(IMG, offset=P2 * 512)
    for name, data in files:
        fs.writebytes("/" + name, data)
    for name in delete:
        fs.remove("/" + name)
    fs.close()


def read(name):
    fs = PyFatFS(IMG, offset=P2 * 512, read_only=True)
    try:
        return fs.readbytes("/" + name)
    finally:
        fs.close()


def fsck():
    part = IMG + ".p2"
    with open(IMG, "rb") as f, open(part, "wb") as o:
        f.seek(P2 * 512)
        o.write(f.read(P2_LEN * 512))
    r = subprocess.run(["fsck.fat", "-n", part], capture_output=True, text=True)
    os.remove(part)
    return r.returncode == 0, r.stdout + r.stderr


def run(mode):
    r = subprocess.run([HOST, IMG, mode], capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def snapshot():
    fs = PyFatFS(IMG, offset=P2 * 512, read_only=True)
    try:
        return {n: fs.readbytes("/" + n) for n in sorted(fs.listdir("/"))}
    finally:
        fs.close()


fails = 0


def check(what, ok, detail=""):
    global fails
    print(f"  {what:<44} {'PASS' if ok else 'FAIL'} {detail if not ok else ''}")
    fails += not ok


send = os.urandom(300001)

# 1. fragmented SEND.BIN (fills the hole X.BIN leaves, continues after Y.BIN),
#    old RECV.BIN replaced, chain freed, both FAT copies kept equal.
make_image([("X.BIN", os.urandom(10000)), ("Y.BIN", os.urandom(10000)),
            ("RECV.BIN", os.urandom(5000))], delete=["X.BIN"])
fs = PyFatFS(IMG, offset=P2 * 512)
fs.writebytes("/SEND.BIN", send)
fs.close()
rc, out = run("copy")
check("copy fragmented SEND.BIN over old RECV.BIN", rc == 0, out)
check("RECV.BIN == SEND.BIN (pyfatfs)", read("RECV.BIN") == send)
ok, log = fsck()
check("fsck.fat clean", ok, log)

# 2. no commit: same files, same contents, still clean
before = snapshot()
rc, out = run("nocommit")
check("uncommitted write leaves files unchanged", rc == 0 and snapshot() == before, out)
ok, log = fsck()
check("fsck.fat clean", ok, log)

# 3. new RECV.BIN (no old entry), empty file
make_image([("SEND.BIN", b"")])
rc, out = run("copy")
check("empty SEND.BIN -> new RECV.BIN", rc == 0 and read("RECV.BIN") == b"", out)
ok, log = fsck()
check("fsck.fat clean", ok, log)

# 4. size not a multiple of the cluster, new entry
make_image([("SEND.BIN", send[:1000])])
rc, out = run("copy")
check("1000-byte SEND.BIN -> new RECV.BIN", rc == 0 and read("RECV.BIN") == send[:1000], out)
ok, log = fsck()
check("fsck.fat clean", ok, log)

# 5. the board-side formatter (tests/src/sd_format.c) on a card that was GPT
#    with junk everywhere: MBR + FAT32 that fsck.fat and pyfatfs accept, then
#    the same copy as above works on it.
with open(IMG, "wb") as f:
    f.write(os.urandom((P2 + P2_LEN) * 512))
rc, out = run("format")
check("format a junk card", rc == 0, out)
mbr = open(IMG, "rb").read(512)
parts = [struct.unpack_from("<B3sB3sII", mbr, 446 + 16 * i) for i in range(2)]
check("MBR: p1 raw at 2048, p2 FAT32 at 67584",
      mbr[510:] == b"\x55\xaa" and parts[0][2] == 0xDA and parts[0][4] == P1
      and parts[1][2] == 0x0C and parts[1][4] == 67584, str(parts))
P2_SAVED, P2_LEN_SAVED = P2, P2_LEN
P2, P2_LEN = 67584, parts[1][5]
ok, log = fsck()
check("fsck.fat clean after format", ok, log)
fs = PyFatFS(IMG, offset=P2 * 512)
fs.writebytes("/SEND.BIN", send)
fs.close()
rc, out = run("copy")
check("copy on the formatted card", rc == 0 and read("RECV.BIN") == send, out)
ok, log = fsck()
check("fsck.fat clean", ok, log)
P2, P2_LEN = P2_SAVED, P2_LEN_SAVED

# 6. missing file
rc, out = run("missing")
check("missing file -> FAT_ENOENT", rc == 0, out)

os.remove(IMG)
print(f"FAT32 HOST TEST: {'PASS' if not fails else 'FAIL'} ({fails} failures)")
sys.exit(1 if fails else 0)
