#!/usr/bin/env python3
"""Kta: capture an iPhone's traffic on a Mac over USB and see which app talks to which host.

  kta capture --out iphone.pcapng [--process Name] [--seconds N]
  kta analyze iphone.pcapng [--process Name] [--top N] [--json]
  kta run [--seconds N] [--process Name] [--json]   capture, then analyze
"""
import argparse
import collections
import contextlib
import functools
import hashlib
import hmac
import json
import os
import re
import signal
import socket
import struct
import sys
import threading
from datetime import datetime


__version__ = "0.1.0"


BANNER = r"""
    __   __
   / /__/ /_____ _
  / //_/ __/ __ `/
 / ,< / /_/ /_/ /
/_/|_|\__/\__,_/"""


def print_banner():
    dim, off = ("\033[2m", "\033[0m") if sys.stderr.isatty() else ("", "")
    print(f"{BANNER}   {dim}v{__version__}{off}\n", file=sys.stderr)
    print(f"{dim}        iPhone traffic, cut by app{off}\n", file=sys.stderr)


# ---------------------------------------------------------------- capture ---


def _patch_pcapd():
    """Skip malformed service packets (newer iOS sends 1-byte frames that crash pymobiledevice3)."""
    from typing import cast

    from pymobiledevice3.services import pcapd

    async def watch(self, packets_count=-1, process=None, interface_name=None):
        index = 0
        while index != packets_count:
            d = await self.service.recv_plist()
            if not d:
                break
            if not isinstance(d, (bytes, bytearray)) or len(d) < 4:
                continue
            try:
                packet = pcapd.parse_device_packet(cast(bytes, d))
            except Exception:
                continue
            if process is not None and process != str(packet.pid) and process != packet.comm:
                continue
            if interface_name is not None and interface_name != packet.interface_name:
                continue
            packet.interface_type = pcapd.INTERFACE_NAMES(packet.interface_type)
            packet.protocol_family = pcapd.CrossPlatformAddressFamily(packet.protocol_family)
            if not packet.frame_pre_length:
                packet.data = pcapd.ETHERNET_HEADER + packet.data
            elif packet.interface_name == "pdp_ip":
                packet.data = pcapd.ETHERNET_HEADER + packet.data[4:]
            yield packet
            index += 1

    pcapd.PcapdService.watch = watch


def cmd_capture(args):
    try:
        from pymobiledevice3.__main__ import main as pmd3_main
    except ImportError:
        sys.exit("pymobiledevice3 is not installed. Run ./install.sh first.")
    _patch_pcapd()
    out = os.path.abspath(args.out)
    argv = ["pymobiledevice3", "pcap", "--out", out]
    if args.process:
        argv += ["--process", args.process]
    # The timer stops the capture with the same SIGINT a Ctrl+C sends. It is a daemon and is cancelled as soon
    # as the capture ends, so stopping early does not leave it to fire later (or keep kta alive until it does).
    timer = None
    if args.seconds:
        timer = threading.Timer(args.seconds, lambda: os.kill(os.getpid(), signal.SIGINT))
        timer.daemon = True
        timer.start()
    print(f"[kta] capturing to {out}" + (f" for {args.seconds}s" if args.seconds else " (Ctrl+C to stop)"),
          file=sys.stderr)
    sys.argv = argv
    try:
        with open(os.devnull, "w") as quiet, contextlib.redirect_stdout(quiet):
            pmd3_main()
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        if e.code not in (0, None, 130):
            raise
    finally:
        if timer:
            timer.cancel()
    size = os.path.getsize(out) if os.path.exists(out) else 0
    print(f"[kta] saved {out} ({size / 1e6:.1f} MB)", file=sys.stderr)
    return out


# ------------------------------------------------------------------ parse ---


def _dns_name(m, i):
    out = []
    for _ in range(20):
        if i >= len(m) or m[i] == 0 or m[i] & 0xC0:
            break
        out.append(m[i + 1:i + 1 + m[i]].decode("ascii", "replace"))
        i += m[i] + 1
    return ".".join(out)


def _tls_sni(p):
    try:
        if p[0] != 0x16 or p[5] != 1:
            return None
        i = 43
        i += 1 + p[i]
        i += 2 + struct.unpack_from(">H", p, i)[0]
        i += 1 + p[i]
        end = i + 2 + struct.unpack_from(">H", p, i)[0]
        i += 2
        while i + 4 <= end:
            t, ln = struct.unpack_from(">HH", p, i)
            i += 4
            if t == 0:
                return p[i + 5:i + 5 + struct.unpack_from(">H", p, i + 3)[0]].decode()
            i += ln
    except Exception:
        return None
    return None


def _dns_skip_name(m, i):
    while True:
        n = m[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def _dns_answers(m):
    """The question of a DNS response and the A/AAAA addresses in its answers (CNAME chains included)."""
    try:
        qd, an = struct.unpack_from(">HH", m, 4)
        if qd != 1:
            return None, []
        name = _dns_name(m, 12)
        i = _dns_skip_name(m, 12) + 4
        addrs = []
        for _ in range(an):
            i = _dns_skip_name(m, i)
            rtype, _, _, rlen = struct.unpack_from(">HHIH", m, i)
            i += 10
            if rtype == 1 and rlen == 4:
                addrs.append(socket.inet_ntoa(m[i:i + 4]))
            elif rtype == 28 and rlen == 16:
                addrs.append(socket.inet_ntop(socket.AF_INET6, m[i:i + 16]))
            i += rlen
        return name, addrs
    except (IndexError, struct.error, OSError):
        return None, []


# ------------------------------------------------------------------- quic ---
# A QUIC client Initial is encrypted with keys derived from its destination connection ID and a salt published
# in the RFC, so anyone on the path can read the TLS ClientHello inside it, and the server name with it.
# RFC 9001 section 5 (v1) and RFC 9369 (v2).


QUIC_VERSIONS = {  # version: (initial salt, label prefix, Initial type, Retry type)
    0x00000001: (bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), "quic ", 0, 3),
    0x6B3343CF: (bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"), "quicv2 ", 1, 0),
}


def _hkdf_expand_label(secret, label, length):
    full = b"tls13 " + label
    info = struct.pack(">HB", length, len(full)) + full + b"\x00"
    out, block, n = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([n]), hashlib.sha256).digest()
        out += block
        n += 1
    return out[:length]


@functools.lru_cache(maxsize=4096)
def quic_initial_keys(dcid, version=1):
    """(key, iv, header protection key) of the client's Initial packets."""
    salt, prefix = QUIC_VERSIONS[version][:2]
    client = _hkdf_expand_label(hmac.new(salt, dcid, hashlib.sha256).digest(), b"client in", 32)
    return tuple(_hkdf_expand_label(client, (prefix + part).encode(), size)
                 for part, size in (("key", 16), ("iv", 12), ("hp", 16)))


def _varint(b, i):
    size = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, size):
        v = v << 8 | b[i + k]
    return v, i + size


def _quic_crypto():
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return None
    return InvalidTag, Cipher, algorithms, modes, AESGCM


_CRYPTO = _quic_crypto()


def quic_client_initials(dgram):
    """For each client Initial packet in a UDP datagram: (DCID, [(offset, data) of its CRYPTO frames])."""
    i = 0
    while i + 7 < len(dgram):
        first = dgram[i]
        if first & 0xC0 != 0xC0:  # short header (or not QUIC): nothing more to read in the clear
            return
        version = struct.unpack_from(">I", dgram, i + 1)[0]
        if version not in QUIC_VERSIONS:
            return
        _, _, initial, retry = QUIC_VERSIONS[version]
        ptype = (first >> 4) & 3
        if ptype == retry:
            return
        p = i + 5
        dcid = bytes(dgram[p + 1:p + 1 + dgram[p]])
        p += 1 + dgram[p]
        p += 1 + dgram[p]
        if ptype == initial:
            token, p = _varint(dgram, p)
            p += token
        length, p = _varint(dgram, p)
        end = p + length
        if end > len(dgram):
            return
        if ptype == initial:
            frames = _quic_decrypt(bytes(dgram[i:end]), p - i, dcid, version)
            if frames is not None:
                yield dcid, frames
        i = end


def _quic_decrypt(pkt, pn_offset, dcid, version):
    if _CRYPTO is None:
        return None
    InvalidTag, Cipher, algorithms, modes, AESGCM = _CRYPTO
    key, iv, hp = quic_initial_keys(dcid, version)
    sample = pkt[pn_offset + 4:pn_offset + 20]
    if len(sample) < 16:
        return None
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    first = pkt[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 3) + 1
    pn = bytes(a ^ b for a, b in zip(pkt[pn_offset:pn_offset + pn_len], mask[1:]))
    header = bytes([first]) + pkt[1:pn_offset] + pn
    nonce = (int.from_bytes(iv, "big") ^ int.from_bytes(pn, "big")).to_bytes(12, "big")
    try:
        plain = AESGCM(key).decrypt(nonce, pkt[pn_offset + pn_len:], header)
    except InvalidTag:
        return None
    return _crypto_frames(plain)


def _crypto_frames(b):
    out, i = [], 0
    try:
        while i < len(b):
            t = b[i]
            if t in (0x00, 0x01):  # PADDING, PING
                i += 1
            elif t in (0x02, 0x03):  # ACK
                _, i = _varint(b, i + 1)
                _, i = _varint(b, i)
                ranges, i = _varint(b, i)
                _, i = _varint(b, i)
                for _ in range(2 * ranges + (3 if t == 0x03 else 0)):
                    _, i = _varint(b, i)
            elif t == 0x06:  # CRYPTO
                off, i = _varint(b, i + 1)
                size, i = _varint(b, i)
                out.append((off, b[i:i + size]))
                i += size
            else:
                break
    except IndexError:
        pass
    return out


def _client_hello_sni(chunks):
    """Server name from CRYPTO frames, once they hold a whole ClientHello; None while it is incomplete."""
    stream = bytearray()
    for off, data in sorted(chunks):
        if off > len(stream):
            break
        stream[off:off + len(data)] = data
    if len(stream) < 4 or stream[0] != 1:
        return None
    size = int.from_bytes(stream[1:4], "big") + 4
    if len(stream) < size:
        return None
    return _tls_sni(b"\x16\x03\x01" + struct.pack(">H", size) + bytes(stream[:size])) or ""


# ---------------------------------------------------------------- analyze ---


class Analysis:
    def __init__(self):
        self.total = 0
        self.procs = collections.Counter()
        self.hosts = collections.defaultdict(collections.Counter)  # app -> "tls name" / "dns name" / "quic name"
        self.conns = collections.defaultdict(collections.Counter)  # app -> (kind, ip, port)
        self.seen = collections.defaultdict(dict)  # app -> ip -> name the app itself asked for (TLS or QUIC)
        self.dns = {}  # ip -> name, from every DNS answer in the capture (iOS resolves for apps in mDNSResponder)
        self._quic = {}  # (app, dcid) -> CRYPTO frames so far; None once the server name is read
        self._tcp = {}  # (app, src, sport, dst, dport) -> [first seq, segments]; None once the hello is read

    def name_of(self, app, ip):
        return self.seen[app].get(ip) or self.dns.get(ip)

    def _quic_initial(self, app, dst, dgram):
        for dcid, frames in quic_client_initials(dgram):
            key = (app, dcid)
            chunks = self._quic.setdefault(key, [])
            if chunks is None:
                continue
            chunks += frames
            sni = _client_hello_sni(chunks)
            if sni is not None or sum(len(d) for _, d in chunks) > 65536:
                self._quic[key] = None
            if sni:
                self.hosts[app]["quic " + sni] += 1
                self.seen[app].setdefault(dst, sni)

    def inspect(self, pkt, app, count):
        if len(pkt) < 34:
            return
        et = struct.unpack_from(">H", pkt, 12)[0]
        ip = pkt[14:]
        if et == 0x0800 and len(ip) > 20:
            proto, tp = ip[9], ip[(ip[0] & 15) * 4:]
            src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        elif et == 0x86DD and len(ip) > 40:
            proto, tp = ip[6], ip[40:]
            src, dst = socket.inet_ntop(socket.AF_INET6, ip[8:24]), socket.inet_ntop(socket.AF_INET6, ip[24:40])
        else:
            return
        if proto == 17 and len(tp) > 20:
            sp, dp = struct.unpack_from(">HH", tp)
            pay = tp[8:]
            if sp == 53 and len(pay) > 12 and pay[2] & 0x80:  # a DNS answer, whoever it was for
                name, addrs = _dns_answers(pay)
                for a in addrs:
                    self.dns.setdefault(a, name)
        if not count or dst.startswith(("fd", "fe80")):
            return
        if proto == 17 and len(tp) > 20:
            if dp in (53, 5353) and len(pay) > 12 and not pay[2] & 0x80:
                n = _dns_name(pay, 12)
                if n:
                    self.hosts[app]["dns " + n] += 1
            elif dp == 443:
                self.conns[app][("quic", dst, dp)] += 1
                self._quic_initial(app, dst, pay)
        elif proto == 6 and len(tp) >= 20:
            sp, dp, seq = struct.unpack_from(">HHI", tp)
            pay = tp[(tp[12] >> 4) * 4:]
            flow = (app, src, sp, dst, dp)
            if pay:
                self._tls_segment(app, flow, seq, pay)
            elif tp[13] & 0x12 == 0x02:
                self.conns[app][("tcp", dst, dp)] += 1
                self._tcp[flow] = [(seq + 1) & 0xFFFFFFFF, []]  # the first data byte follows the SYN

    def _tls_segment(self, app, flow, seq, pay):
        """Collect a connection's first bytes until they hold the whole TLS ClientHello record."""
        state = self._tcp.get(flow, ())
        if state is None:
            return
        if not state:  # no SYN in the capture: start from this segment, if it opens a TLS handshake
            if pay[0] != 0x16:
                self._tcp[flow] = None
                return
            state = self._tcp[flow] = [seq, []]
        state[1].append(((seq - state[0]) & 0xFFFFFFFF, pay))
        stream = bytearray()
        for off, data in sorted(state[1]):
            if off > len(stream) or off > 65536:
                break
            stream[off:off + len(data)] = data
        if stream and stream[0] != 0x16:  # the connection does not start with TLS
            self._tcp[flow] = None
            return
        need = 5 + struct.unpack_from(">H", stream, 3)[0] if len(stream) >= 5 else None
        if need is None or len(stream) < need:
            if sum(len(d) for _, d in state[1]) > 65536:
                self._tcp[flow] = None
            return
        self._tcp[flow] = None
        sni = _tls_sni(bytes(stream[:need]))
        if sni:
            self.hosts[app]["tls " + sni] += 1
            self.seen[app].setdefault(flow[3], sni)


def read_packets(path):
    """Yield (packet bytes, options bytes) of each Enhanced Packet Block, one block at a time."""
    with open(path, "rb") as f:
        order = "<"
        while True:
            head = f.read(8)
            if len(head) < 8:
                return
            btype = struct.unpack_from("<I", head)[0]
            if btype == 0x0A0D0D0A:  # Section Header: its byte-order magic sets the order of what follows
                magic = f.read(4)
                if len(magic) < 4:
                    return
                order = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
                blen = struct.unpack_from(order + "I", head, 4)[0]
                rest = magic + f.read(blen - 12)
            else:
                btype, blen = struct.unpack(order + "II", head)
                if blen < 12:
                    return
                rest = f.read(blen - 8)
            if len(rest) < blen - 8:
                return
            if btype == 6:
                cap = struct.unpack_from(order + "I", rest, 12)[0]
                yield rest[20:20 + cap], rest[20 + ((cap + 3) & ~3):-4]


def analyze(path, process=None):
    result = Analysis()
    for pkt, opts in read_packets(path):
        m = re.search(rb"ProcName: ([^,\x00]*)", opts)
        name = (m.group(1).decode(errors="replace") if m else "") or "(unattributed)"
        # Every packet is read for DNS answers, since the app's own lookups are made by mDNSResponder;
        # only the chosen app's packets are counted.
        count = not process or name == process
        if count:
            result.total += 1
            result.procs[name] += 1
        result.inspect(pkt, name, count)
    return result


def report(r, top=None):
    """The analysis as plain data: apps by packet count, each with its hosts and connections."""
    apps = []
    for app, count in r.procs.most_common(top):
        hosts = [{"kind": h.split(" ", 1)[0], "name": h.split(" ", 1)[1], "count": c}
                 for h, c in r.hosts[app].most_common(top)]
        conns = [{"kind": kind, "ip": ip, "port": port, "name": r.name_of(app, ip), "count": c}
                 for (kind, ip, port), c in r.conns[app].most_common(top)]
        apps.append({"name": app, "packets": count, "hosts": hosts, "connections": conns})
    return {"packets": r.total, "apps": apps}


def cmd_analyze(args):
    r = analyze(args.file, args.process)
    if _CRYPTO is None:
        print("[kta] the cryptography package is missing: QUIC server names are not read", file=sys.stderr)
    if args.json:
        data = {"file": args.file, **report(r, args.top)}
        json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
        print()
        return
    print(f"{args.file}: {r.total} packets\n")
    for app in report(r, args.top or 12)["apps"]:
        print(f"{app['name']}  ({app['packets']} packets)")
        for h in app["hosts"]:
            print(f"  {h['count']:5d}  {h['kind']} {h['name']}")
        for c in app["connections"]:
            addr = c["ip"] if c["kind"] == "quic" else f"{c['ip']}:{c['port']}"
            label = f"{c['name']} ({addr})" if c["name"] else addr
            print(f"  {c['count']:5d}  {c['kind']} {label}")
        print()


def cmd_run(args):
    out = args.out or datetime.now().strftime("kta-%Y%m%d-%H%M%S.pcapng")
    args.out = out
    cmd_capture(args)
    args.file = out
    cmd_analyze(args)


def main():
    ap = argparse.ArgumentParser(prog="kta", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("-s", "--silent", action="store_true", help="do not print the banner")
    ap.add_argument("--version", action="version", version=f"kta {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("capture", help="record iPhone traffic over USB")
    c.add_argument("--out", required=True)
    c.add_argument("--process")
    c.add_argument("--seconds", type=int)
    c.set_defaults(fn=cmd_capture)

    a = sub.add_parser("analyze", help="list hosts and IPs per app")
    a.add_argument("file")
    a.add_argument("--process")
    a.add_argument("--top", type=int, help="apps and lines per app to show (text: 12, JSON: all)")
    a.add_argument("--json", action="store_true", help="print the result as JSON on stdout")
    a.set_defaults(fn=cmd_analyze)

    r = sub.add_parser("run", help="capture, then analyze")
    r.add_argument("--out")
    r.add_argument("--process")
    r.add_argument("--seconds", type=int, default=60)
    r.add_argument("--top", type=int, help="apps and lines per app to show (text: 12, JSON: all)")
    r.add_argument("--json", action="store_true", help="print the result as JSON on stdout")
    r.set_defaults(fn=cmd_run)

    args = ap.parse_args()
    if not args.silent:
        print_banner()
    args.fn(args)

if __name__ == "__main__":
    main()
