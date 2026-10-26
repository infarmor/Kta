#!/usr/bin/env python3
"""Kta: capture an iPhone's traffic on a Mac over USB and see which app talks to which host.

  kta capture --out iphone.pcapng [--process Name] [--seconds N]
  kta analyze iphone.pcapng [--process Name] [--top N]
  kta run [--seconds N] [--process Name]      capture, then analyze
"""
import argparse
import collections
import contextlib
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
    __    __
   / /__ / /_____ _
  / //_// __/ __ `/
 / ,<  / /_/ /_/ /
/_/|_| \__/\__,_/
 (o)==[#]===========================---->
"""


def print_banner():
    red, dim, off = ("\033[31m", "\033[2m", "\033[0m") if sys.stderr.isatty() else ("", "", "")
    print(f"{red}{BANNER}{off}", file=sys.stderr)
    print(f"{dim}  iPhone traffic, cut by app          v{__version__}{off}\n", file=sys.stderr)


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


def analyze(path, process=None):
    data = open(path, "rb").read()
    procs = collections.Counter()
    hosts = collections.defaultdict(collections.Counter)
    ips = collections.defaultdict(collections.Counter)
    total = 0
    o = 0
    while o + 12 <= len(data):
        btype, blen = struct.unpack_from("<II", data, o)
        if blen < 12 or o + blen > len(data):
            break
        if btype == 6:
            cap = struct.unpack_from("<I", data, o + 20)[0]
            pkt = data[o + 28:o + 28 + cap]
            opts = data[o + 28 + ((cap + 3) & ~3):o + blen - 4]
            m = re.search(rb"ProcName: ([^,]*),", opts)
            name = (m.group(1).decode(errors="replace") if m else "") or "(unattributed)"
            if process and name != process:
                o += blen
                continue
            total += 1
            procs[name] += 1
            _inspect(pkt, name, hosts, ips)
        o += blen
    return total, procs, hosts, ips


def _inspect(pkt, name, hosts, ips):
    if len(pkt) < 34:
        return
    et = struct.unpack_from(">H", pkt, 12)[0]
    ip = pkt[14:]
    if et == 0x0800 and len(ip) > 20:
        proto, dst, tp = ip[9], socket.inet_ntoa(ip[16:20]), ip[(ip[0] & 15) * 4:]
    elif et == 0x86DD and len(ip) > 40:
        proto, dst, tp = ip[6], socket.inet_ntop(socket.AF_INET6, ip[24:40]), ip[40:]
    else:
        return
    if dst.startswith(("fd", "fe80")):
        return
    if proto == 17 and len(tp) > 20:
        dp = struct.unpack_from(">H", tp, 2)[0]
        pay = tp[8:]
        if dp in (53, 5353) and len(pay) > 12 and not pay[2] & 0x80:
            n = _dns_name(pay, 12)
            if n:
                hosts[name]["dns " + n] += 1
        elif dp == 443:
            ips[name]["quic " + dst] += 1
    elif proto == 6 and len(tp) > 20:
        dp = struct.unpack_from(">H", tp, 2)[0]
        pay = tp[(tp[12] >> 4) * 4:]
        sni = _tls_sni(pay) if pay else None
        if sni:
            hosts[name]["tls " + sni] += 1
        elif tp[13] & 0x12 == 0x02:
            ips[name][f"tcp {dst}:{dp}"] += 1


def cmd_analyze(args):
    total, procs, hosts, ips = analyze(args.file, args.process)
    print(f"{args.file}: {total} packets\n")
    for name, count in procs.most_common(args.top):
        print(f"{name}  ({count} packets)")
        for h, c in hosts[name].most_common(args.top):
            print(f"  {c:5d}  {h}")
        for h, c in ips[name].most_common(5):
            print(f"  {c:5d}  {h}")
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
    a.set_defaults(fn=cmd_analyze)

    r = sub.add_parser("run", help="capture, then analyze")
    r.add_argument("--out")
    r.add_argument("--process")
    r.add_argument("--seconds", type=int, default=60)
    r.set_defaults(fn=cmd_run)

    args = ap.parse_args()
    if not args.silent:
        print_banner()
    args.fn(args)


if __name__ == "__main__":
    main()
