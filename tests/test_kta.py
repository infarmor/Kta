"""Tests for kta. Run from the repository root: python3 -m unittest discover tests"""
import contextlib
import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import kta  # noqa: E402

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
PHONE = "192.168.1.20"


# ------------------------------------------------------------ packet makers ---

def _pad4(b):
    return b + b"\0" * (-len(b) % 4)


def write_pcapng(path, packets):
    """packets: [(ethernet frame, ProcName or None)] as pcapd would record them."""
    out = io.BytesIO()
    shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out.write(struct.pack("<II", 0x0A0D0D0A, 12 + len(shb)) + shb + struct.pack("<I", 12 + len(shb)))
    idb = struct.pack("<HHI", 1, 0, 65535)
    out.write(struct.pack("<II", 1, 12 + len(idb)) + idb + struct.pack("<I", 12 + len(idb)))
    for frame, proc in packets:
        opts = b""
        if proc is not None:
            comment = f"PID: 100, ProcName: {proc}".encode()
            opts = struct.pack("<HH", 1, len(comment)) + _pad4(comment) + struct.pack("<HH", 0, 0)
        body = struct.pack("<IIIII", 0, 0, 0, len(frame), len(frame)) + _pad4(frame) + opts
        out.write(struct.pack("<II", 6, 12 + len(body)) + body + struct.pack("<I", 12 + len(body)))
    with open(path, "wb") as f:
        f.write(out.getvalue())


def ipv4_udp(src, dst, sport, dport, payload):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return b"\0" * 12 + b"\x08\x00" + ip + udp


def ipv4_tcp(src, dst, sport, dport, seq, payload=b"", flags=0x18):
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, 0, 5 << 4, flags, 65535, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return b"\0" * 12 + b"\x08\x00" + ip + tcp


def tls_record(handshake):
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def dns_response(name, addrs, cname=None):
    def enc(n):
        return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\0"
    answers = b""
    owner = b"\xc0\x0c"
    if cname:
        answers += owner + struct.pack(">HHIH", 5, 1, 60, len(enc(cname))) + enc(cname)
    for a in addrs:
        answers += owner + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(a)
    count = len(addrs) + (1 if cname else 0)
    return struct.pack(">HHHHHH", 7, 0x8180, 1, count, 0, 0) + enc(name) + struct.pack(">HH", 1, 1) + answers


def client_hello(sni, padding=0):
    server_name = struct.pack(">HBH", len(sni) + 3, 0, len(sni)) + sni.encode()
    exts = struct.pack(">HH", 21, padding) + b"\0" * padding  # before the name, so the name is in the tail
    exts += struct.pack(">HH", 0, len(server_name)) + server_name
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack(">H", len(exts)) + exts
    return b"\x01" + len(body).to_bytes(3, "big") + body


def _v(n):
    return struct.pack(">H", 0x4000 | n)


def quic_initial(dcid, pn, frames):
    """A protected QUIC v1 client Initial carrying the given CRYPTO frames [(offset, data)]."""
    key, iv, hp = kta.quic_initial_keys(dcid, 1)
    plain = b"".join(b"\x06" + _v(off) + _v(len(d)) + d for off, d in frames)
    plain += b"\0" * max(0, 1100 - len(plain))
    pn_bytes = struct.pack(">I", pn)
    head = bytes([0xC3]) + struct.pack(">I", 1) + bytes([len(dcid)]) + dcid + b"\x00" + b"\x00"
    head += _v(len(pn_bytes) + len(plain) + 16)
    nonce = (int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big")
    sealed = AESGCM(key).encrypt(nonce, plain, head + pn_bytes)
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sealed[:16]) + enc.finalize()
    first = head[0] ^ (mask[0] & 0x0F)
    pn_prot = bytes(a ^ b for a, b in zip(pn_bytes, mask[1:5]))
    return bytes([first]) + head[1:] + pn_prot + sealed


# -------------------------------------------------------------------- tests ---

class QuicTest(unittest.TestCase):
    def test_initial_keys_match_rfc9001_appendix_a(self):
        key, iv, hp = kta.quic_initial_keys(bytes.fromhex("8394c8f03e515708"), 1)
        self.assertEqual(key.hex(), "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(iv.hex(), "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(hp.hex(), "9f50449e04a0e810283a1e9933adedd2")

    def test_reads_server_name_from_real_client_initials_v1_and_v2(self):
        # Datagrams written by aioquic connecting to i.pinimg.com, once with QUIC v1 and once with v2.
        with open(os.path.join(FIXTURES, "quic_initials.hex")) as f:
            datagrams = [bytes.fromhex(line) for line in f.read().split()]
        self.assertEqual(len(datagrams), 2)
        for dgram in datagrams:
            initials = list(kta.quic_client_initials(dgram))
            self.assertEqual(len(initials), 1)
            self.assertEqual(kta._client_hello_sni(initials[0][1]), "i.pinimg.com")

    def test_client_hello_split_over_two_initials_out_of_order(self):
        hello = client_hello("api.pinterest.com", padding=1500)  # as large as a post-quantum key share makes it
        dcid = bytes.fromhex("0102030405060708")
        first = quic_initial(dcid, 0, [(0, hello[:1000])])
        second = quic_initial(dcid, 1, [(1000, hello[1000:])])
        path = os.path.join(self.tmp, "q.pcapng")
        write_pcapng(path, [(ipv4_udp(PHONE, "2.22.237.73", 50000, 443, second), "Pinterest"),
                            (ipv4_udp(PHONE, "2.22.237.73", 50000, 443, first), "Pinterest")])
        r = kta.analyze(path)
        self.assertEqual(r.hosts["Pinterest"]["quic api.pinterest.com"], 1)
        self.assertEqual(r.name_of("Pinterest", "2.22.237.73"), "api.pinterest.com")

    def test_garbage_on_udp_443_is_ignored(self):
        self.assertEqual(list(kta.quic_client_initials(b"\xc3\x00\x00\x00\x01" + b"\x08" * 50)), [])
        self.assertEqual(list(kta.quic_client_initials(b"\x40" + b"\x00" * 50)), [])

    def setUp(self):
        self.tmp = tempfile.mkdtemp()


class DnsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        short_header = b"\x41" + b"\x00" * 60  # 1-RTT QUIC: nothing readable
        self.path = os.path.join(self.tmp, "d.pcapng")
        write_pcapng(self.path, [
            (ipv4_udp("192.168.1.1", PHONE, 53, 5000,
                      dns_response("i.pinimg.com", ["2.22.237.73", "2.22.237.74"], cname="cdn.example.net")),
             "mDNSResponder"),
            (ipv4_udp(PHONE, "2.22.237.73", 50000, 443, short_header), "Pinterest"),
            (ipv4_udp(PHONE, "2.22.237.73", 50000, 443, short_header), "Pinterest"),
            (ipv4_udp(PHONE, "9.9.9.9", 50001, 443, short_header), "Pinterest"),
        ])

    def test_answers_from_mdnsresponder_name_the_apps_ips(self):
        r = kta.analyze(self.path)
        self.assertEqual(r.dns["2.22.237.73"], "i.pinimg.com")
        self.assertEqual(r.dns["2.22.237.74"], "i.pinimg.com")
        out = self._render(r)
        self.assertIn("quic i.pinimg.com (2.22.237.73)", out)
        self.assertIn("quic 9.9.9.9", out)

    def test_process_filter_still_uses_other_processes_dns(self):
        r = kta.analyze(self.path, "Pinterest")
        self.assertEqual(list(r.procs), ["Pinterest"])
        self.assertEqual(r.total, 3)
        self.assertEqual(r.name_of("Pinterest", "2.22.237.73"), "i.pinimg.com")

    def test_procname_as_last_field(self):
        self.assertEqual(set(kta.analyze(self.path).procs), {"mDNSResponder", "Pinterest"})

    def _render(self, r):
        args = types.SimpleNamespace(file=self.path, process=None, top=None, json=False)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            kta.cmd_analyze(args)
        return buf.getvalue()


class TcpTest(unittest.TestCase):
    def test_client_hello_split_over_tcp_segments_out_of_order(self):
        record = tls_record(client_hello("api.pinterest.com", padding=1800))
        seq = 0xFFFFFF00  # the sequence number wraps inside the hello
        segs = [(seq + i, record[i:i + 700]) for i in range(0, len(record), 700)]
        path = os.path.join(tempfile.mkdtemp(), "t.pcapng")
        frames = [ipv4_tcp(PHONE, "151.101.0.84", 50000, 443, seq - 1, flags=0x02)]
        frames += [ipv4_tcp(PHONE, "151.101.0.84", 50000, 443, s, d) for s, d in (segs[1], segs[0], *segs[2:])]
        frames.append(ipv4_tcp(PHONE, "151.101.0.84", 50000, 443, seq + len(record), b"\x17" * 50))
        write_pcapng(path, [(f, "Pinterest") for f in frames])
        r = kta.analyze(path)
        self.assertEqual(dict(r.hosts["Pinterest"]), {"tls api.pinterest.com": 1})
        self.assertEqual(r.name_of("Pinterest", "151.101.0.84"), "api.pinterest.com")
        self.assertEqual(r.conns["Pinterest"][("tcp", "151.101.0.84", 443)], 1)

    def test_non_tls_flow_is_dropped_at_once(self):
        path = os.path.join(tempfile.mkdtemp(), "h.pcapng")
        write_pcapng(path, [(ipv4_tcp(PHONE, "1.2.3.4", 50000, 80, 1, b"GET / HTTP/1.1\r\n"), "Safari")])
        r = kta.analyze(path)
        self.assertEqual(dict(r.hosts["Safari"]), {})
        self.assertEqual(list(r._tcp.values()), [None])


class OutputTest(unittest.TestCase):
    def test_json(self):
        path = os.path.join(tempfile.mkdtemp(), "j.pcapng")
        write_pcapng(path, [
            (ipv4_udp("192.168.1.1", PHONE, 53, 5000, dns_response("example.com", ["93.184.216.34"])),
             "mDNSResponder"),
            (ipv4_tcp(PHONE, "93.184.216.34", 50000, 443, 1, flags=0x02), "Safari"),
        ])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            kta.cmd_analyze(types.SimpleNamespace(file=path, process=None, top=None, json=True))
        data = json.loads(buf.getvalue())
        self.assertEqual(data["packets"], 2)
        safari = next(a for a in data["apps"] if a["name"] == "Safari")
        self.assertEqual(safari["connections"], [
            {"kind": "tcp", "ip": "93.184.216.34", "port": 443, "name": "example.com", "count": 1}])

    def test_big_endian_section_and_truncated_tail(self):
        path = os.path.join(tempfile.mkdtemp(), "be.pcapng")
        frame = ipv4_tcp(PHONE, "1.2.3.4", 50000, 443, 1, flags=0x02)
        comment = b"ProcName: Mail"
        opts = struct.pack(">HH", 1, len(comment)) + _pad4(comment) + struct.pack(">HH", 0, 0)
        body = struct.pack(">IIIII", 0, 0, 0, len(frame), len(frame)) + _pad4(frame) + opts
        shb = struct.pack(">IHHq", 0x1A2B3C4D, 1, 0, -1)
        with open(path, "wb") as f:
            f.write(struct.pack(">II", 0x0A0D0D0A, 12 + len(shb)) + shb + struct.pack(">I", 12 + len(shb)))
            f.write(struct.pack(">II", 6, 12 + len(body)) + body + struct.pack(">I", 12 + len(body)))
            f.write(struct.pack(">II", 6, 400) + b"\0" * 30)  # capture cut off mid-block
        r = kta.analyze(path)
        self.assertEqual(dict(r.procs), {"Mail": 1})


class CaptureTimerTest(unittest.TestCase):
    def test_timer_is_cancelled_when_capture_ends_early(self):
        fake = types.ModuleType("pymobiledevice3.__main__")
        fake.main = lambda: None  # the capture stops at once, as if Ctrl+C was pressed
        saved = {k: sys.modules.get(k) for k in ("pymobiledevice3", "pymobiledevice3.__main__")}
        sys.modules["pymobiledevice3"] = types.ModuleType("pymobiledevice3")
        sys.modules["pymobiledevice3.__main__"] = fake
        patch, kta._patch_pcapd = kta._patch_pcapd, lambda: None
        try:
            args = types.SimpleNamespace(out=os.path.join(tempfile.mkdtemp(), "x.pcapng"), process=None,
                                         seconds=3600)
            with contextlib.redirect_stderr(io.StringIO()):
                kta.cmd_capture(args)
        finally:
            kta._patch_pcapd = patch
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        timers = [t for t in threading.enumerate() if isinstance(t, threading.Timer)]
        for t in timers:
            t.join(1)
        self.assertFalse([t for t in timers if t.is_alive()])


if __name__ == "__main__":
    unittest.main()
