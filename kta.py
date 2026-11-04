#!/usr/bin/env python3
"""Kta: capture an iPhone's traffic on a Mac over USB and see which app talks to which host.

  kta capture --out iphone.pcapng [--process Name] [--seconds N]
  kta analyze iphone.pcapng [--process Name] [--top N] [--json]
  kta run [--seconds N] [--process Name] [--json]      capture, then analyze
"""
import argparse
import collections
import contextlib
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

# What _patch_pcapd uses from pymobiledevice3's internals. A release that renames any of them must stop the
# capture with a clear message instead of failing halfway through.
_PCAPD_NAMES = ("PcapdService", "parse_device_packet", "INTERFACE_NAMES", "CrossPlatformAddressFamily",
                "ETHERNET_HEADER")


def _check_pcapd(pcapd):
    missing = [n for n in _PCAPD_NAMES if not hasattr(pcapd, n)]
    if missing or not hasattr(getattr(pcapd, "PcapdService", None), "watch"):
        try:
            from importlib.metadata import version
            installed = version("pymobiledevice3")
        except Exception:
            installed = "unknown"
        sys.exit(f"pymobiledevice3 {installed} is not compatible with kta (missing: "
                 f"{', '.join(missing) or 'PcapdService.watch'}). Run ./install.sh to install a supported version.")


def _patch_pcapd():
    """Skip malformed service packets (newer iOS sends 1-byte frames that crash pymobiledevice3)."""
    from typing import cast

    from pymobiledevice3.services import pcapd

    _check_pcapd(pcapd)

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
    if args.seconds:
        threading.Timer(args.seconds, lambda: os.kill(os.getpid(), signal.SIGINT)).start()
    print(f"[kta] capturing to {out}" + (f" for {args.seconds}s" if args.seconds else " (Ctrl+C to stop)"),
          file=sys.stderr)
    sys.argv = argv
    try:
        with open(os.devnull, "w") as quiet, contextlib.redirect_stdout(quiet):
            pmd3_main()
    except SystemExit as e:
        if e.code not in (0, None, 130):
            raise
    size = os.path.getsize(out) if os.path.exists(out) else 0
    print(f"[kta] saved {out} ({size / 1e6:.1f} MB)", file=sys.stderr)
    return out


# ---------------------------------------------------------------- analyze ---

def _dns_name(m, i):
    """Read a DNS name at offset i, following compression pointers. Returns (name, offset after it)."""
    out, end, jumps = [], None, 0
    while i < len(m) and len(out) < 64:
        n = m[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:
            if i + 1 >= len(m) or jumps > 10:
                break
            if end is None:
                end = i + 2
            i = ((n & 0x3F) << 8) | m[i + 1]
            jumps += 1
            continue
        if n & 0xC0:
            break
        out.append(m[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += n + 1
    return ".".join(out), (end if end is not None else i)


def _dns_answers(m):
    """IP addresses in a DNS response, each paired with the name that was asked for."""
    out = []
    try:
        qd, an = struct.unpack_from(">HH", m, 4)
        i, asked = 12, ""
        for _ in range(qd):
            name, i = _dns_name(m, i)
            asked = asked or name
            i += 4
        for _ in range(an):
            _, i = _dns_name(m, i)
            rtype, _cls, _ttl, rdlen = struct.unpack_from(">HHIH", m, i)
            i += 10
            rdata = m[i:i + rdlen]
            if rtype == 1 and len(rdata) == 4:
                out.append((socket.inet_ntoa(rdata), asked))
            elif rtype == 28 and len(rdata) == 16:
                out.append((socket.inet_ntop(socket.AF_INET6, rdata), asked))
            i += rdlen
    except (struct.error, IndexError, ValueError, OSError):
        pass
    return [(ip, name) for ip, name in out if name]


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


def _blocks(f):
    """Yield (type, body) for each pcapng block, reading the file a block at a time."""
    while True:
        head = f.read(8)
        if len(head) < 8:
            return
        btype, blen = struct.unpack("<II", head)
        if blen < 12:
            return
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        yield btype, body[:-4]


def analyze(path, process=None):
    procs = collections.Counter()
    hosts = collections.defaultdict(collections.Counter)
    ips = collections.defaultdict(collections.Counter)
    names = {}
    total = 0
    with open(path, "rb") as f:
        for btype, body in _blocks(f):
            if btype != 6 or len(body) < 20:
                continue
            cap = struct.unpack_from("<I", body, 12)[0]
            pkt = body[20:20 + cap]
            opts = body[20 + ((cap + 3) & ~3):]
            m = re.search(rb"ProcName: ([^,]*),", opts)
            name = (m.group(1).decode(errors="replace") if m else "") or "(unattributed)"
            # A DNS answer names its IPs for every app, whichever process received it.
            for ip, host in _dns_reply(pkt):
                names[ip] = host
            if process and name != process:
                continue
            total += 1
            procs[name] += 1
            _inspect(pkt, name, hosts, ips)
    return total, procs, hosts, ips, names


def _ip_layer(pkt):
    """(protocol, destination, transport bytes) of an Ethernet frame, or None."""
    if len(pkt) < 34:
        return None
    et = struct.unpack_from(">H", pkt, 12)[0]
    ip = pkt[14:]
    if et == 0x0800 and len(ip) > 20:
        return ip[9], socket.inet_ntoa(ip[16:20]), ip[(ip[0] & 15) * 4:]
    if et == 0x86DD and len(ip) > 40:
        return ip[6], socket.inet_ntop(socket.AF_INET6, ip[24:40]), ip[40:]
    return None


def _dns_reply(pkt):
    layer = _ip_layer(pkt)
    if not layer or layer[0] != 17 or len(layer[2]) <= 20:
        return []
    tp = layer[2]
    pay = tp[8:]
    if struct.unpack_from(">H", tp, 0)[0] not in (53, 5353) or len(pay) <= 12 or not pay[2] & 0x80:
        return []
    return _dns_answers(pay)


def _inspect(pkt, name, hosts, ips):
    layer = _ip_layer(pkt)
    if not layer:
        return
    proto, dst, tp = layer
    if dst.startswith(("fd", "fe80")):
        return
    if proto == 17 and len(tp) > 20:
        dp = struct.unpack_from(">H", tp, 2)[0]
        pay = tp[8:]
        if dp in (53, 5353) and len(pay) > 12 and not pay[2] & 0x80:
            n = _dns_name(pay, 12)[0]
            if n:
                hosts[name]["dns " + n] += 1
        elif dp == 443:
            ips[name][("quic", dst, "")] += 1
    elif proto == 6 and len(tp) > 20:
        dp = struct.unpack_from(">H", tp, 2)[0]
        pay = tp[(tp[12] >> 4) * 4:]
        sni = _tls_sni(pay) if pay else None
        if sni:
            hosts[name]["tls " + sni] += 1
        elif tp[13] & 0x12 == 0x02:
            ips[name][("tcp", dst, f":{dp}")] += 1


def _label(key, names):
    kind, ip, port = key
    host = names.get(ip)
    return f"{kind} {ip}{port}" + (f"  ({host})" if host else "")


def report(path, total, procs, hosts, ips, names):
    """Everything analyze found, as plain data for --json. Nothing is cut to --top."""
    apps = []
    for name, count in procs.most_common():
        apps.append({
            "name": name,
            "packets": count,
            "hosts": [{"kind": h.split(" ", 1)[0], "name": h.split(" ", 1)[1], "count": c}
                      for h, c in hosts[name].most_common()],
            "connections": [{"kind": kind, "ip": ip, "port": int(port[1:]) if port else None,
                             "name": names.get(ip), "count": c}
                            for (kind, ip, port), c in ips[name].most_common()],
        })
    return {"file": path, "packets": total, "apps": apps}


def cmd_analyze(args):
    total, procs, hosts, ips, names = analyze(args.file, args.process)
    if getattr(args, "json", False):
        json.dump(report(args.file, total, procs, hosts, ips, names), sys.stdout, indent=2, ensure_ascii=False)
        print()
        return
    print(f"{args.file}: {total} packets\n")
    for name, count in procs.most_common(args.top):
        print(f"{name}  ({count} packets)")
        for h, c in hosts[name].most_common(args.top):
            print(f"  {c:5d}  {h}")
        for key, c in ips[name].most_common(5):
            print(f"  {c:5d}  {_label(key, names)}")
        print()


def cmd_run(args):
    out = args.out or datetime.now().strftime("kta-%Y%m%d-%H%M%S.pcapng")
    args.out = out
    cmd_capture(args)
    args.file, args.top = out, 12
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
    a.add_argument("--top", type=int, default=12)
    a.add_argument("--json", action="store_true", help="print the full result as JSON")
    a.set_defaults(fn=cmd_analyze)

    r = sub.add_parser("run", help="capture, then analyze")
    r.add_argument("--out")
    r.add_argument("--process")
    r.add_argument("--seconds", type=int, default=60)
    r.add_argument("--json", action="store_true", help="print the full result as JSON")
    r.set_defaults(fn=cmd_run)

    args = ap.parse_args()
    if not args.silent:
        print_banner()
    args.fn(args)


if __name__ == "__main__":
    main()
