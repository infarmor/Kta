"""Tests for the offline analyzer. They build small pcapng files by hand, so no iPhone is needed."""
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import kta  # noqa: E402

PHONE = "192.168.1.20"
RESOLVER = "192.168.1.1"


def _pad(b):
    return b + b"\0" * (-len(b) % 4)


def _block(btype, body):
    n = 12 + len(body)
    return struct.pack("<II", btype, n) + body + struct.pack("<I", n)


def _pcapng(packets):
    """packets: list of (frame bytes, process name or None)."""
    out = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += _block(1, struct.pack("<HHI", 1, 0, 0))
    for frame, proc in packets:
        opts = b""
        if proc is not None:
            comment = f"PID: 1, ProcName: {proc}, EPID: 1, EProcName: {proc}, SVC: BE".encode()
            opts = struct.pack("<HH", 1, len(comment)) + _pad(comment) + struct.pack("<HH", 0, 0)
        body = struct.pack("<IIIII", 0, 0, 0, len(frame), len(frame)) + _pad(frame) + opts
        out += _block(6, body)
    return out


def _ipv4(src, dst, proto, payload):
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return b"\0" * 12 + b"\x08\x00" + hdr + payload


def _udp(sp, dp, payload):
    return struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload


def _tcp(sp, dp, flags, payload=b""):
    mss = b"\x02\x04\x05\xb4"  # real SYNs always carry options
    return struct.pack(">HHIIBBHHH", sp, dp, 0, 0, 6 << 4, flags, 0, 0, 0) + mss + payload


def _qname(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def _dns_query(name):
    return struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + _qname(name) + struct.pack(">HH", 1, 1)


def _dns_reply(name, cname, ip):
    """Answer for `name` via a CNAME to `cname`, with compression pointers like real resolvers send."""
    msg = struct.pack(">HHHHHH", 1, 0x8180, 1, 2, 0, 0) + _qname(name) + struct.pack(">HH", 1, 1)
    target = _qname(cname)
    msg += b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(target)) + target
    cname_at = len(msg) - len(target)
    msg += struct.pack(">H", 0xC000 | cname_at) + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return msg


def _client_hello(sni):
    host = sni.encode()
    ext_sni = struct.pack(">HHHBH", 0, len(host) + 5, len(host) + 3, 0, len(host)) + host
    body = b"\x03\x03" + b"\0" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack(">H", len(ext_sni)) + ext_sni
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _write(tmp_path, packets):
    path = tmp_path / "t.pcapng"
    path.write_bytes(_pcapng(packets))
    return str(path)


def test_dns_query_tls_sni_and_attribution(tmp_path):
    path = _write(tmp_path, [
        (_ipv4(PHONE, RESOLVER, 17, _udp(50000, 53, _dns_query("api.example.com"))), "App"),
        (_ipv4(PHONE, "93.184.216.34", 6, _tcp(50001, 443, 0x18, _client_hello("api.example.com"))), "App"),
        (_ipv4(PHONE, RESOLVER, 17, _udp(50002, 53, _dns_query("other.test"))), None),
    ])
    total, procs, hosts, ips, names = kta.analyze(path)
    assert total == 3
    assert procs == {"App": 2, "(unattributed)": 1}
    assert hosts["App"] == {"dns api.example.com": 1, "tls api.example.com": 1}
    assert hosts["(unattributed)"] == {"dns other.test": 1}


def test_ips_are_named_from_dns_answers(tmp_path):
    path = _write(tmp_path, [
        # The answer reaches the phone through the system resolver, not the app itself.
        (_ipv4(RESOLVER, PHONE, 17, _udp(53, 50000, _dns_reply("img.example.com", "cdn.example.net", "2.22.237.73"))),
         "mDNSResponder"),
        (_ipv4(PHONE, "2.22.237.73", 17, _udp(50003, 443, b"\xc0" + b"\0" * 30)), "App"),
        (_ipv4(PHONE, "2.22.237.73", 6, _tcp(50004, 443, 0x02)), "App"),
        (_ipv4(PHONE, "8.8.4.4", 6, _tcp(50005, 853, 0x02)), "App"),
    ])
    _, _, _, ips, names = kta.analyze(path, process="App")
    assert names == {"2.22.237.73": "img.example.com"}
    labels = sorted(kta._label(k, names) for k in ips["App"])
    assert labels == [
        "quic 2.22.237.73  (img.example.com)",
        "tcp 2.22.237.73:443  (img.example.com)",
        "tcp 8.8.4.4:853",
    ]


def test_process_filter_excludes_other_apps(tmp_path):
    path = _write(tmp_path, [
        (_ipv4(PHONE, RESOLVER, 17, _udp(50000, 53, _dns_query("a.test"))), "A"),
        (_ipv4(PHONE, RESOLVER, 17, _udp(50001, 53, _dns_query("b.test"))), "B"),
    ])
    total, procs, hosts, _, _ = kta.analyze(path, process="B")
    assert total == 1 and list(procs) == ["B"]
    assert hosts["B"] == {"dns b.test": 1}


def test_truncated_file_stops_cleanly(tmp_path):
    data = _pcapng([(_ipv4(PHONE, RESOLVER, 17, _udp(50000, 53, _dns_query("a.test"))), "A")])
    path = tmp_path / "cut.pcapng"
    path.write_bytes(data[:-10])
    total, *_ = kta.analyze(str(path))
    assert total == 0


def test_malformed_dns_does_not_raise():
    assert kta._dns_answers(b"\0\x01\x81\x80\0\x01\0\x05" + b"\xc0") == []
    # A pointer loop must end.
    assert kta._dns_name(b"\xc0\x00", 0)[0] == ""


def test_report_is_json_ready(tmp_path):
    import json
    path = _write(tmp_path, [
        (_ipv4(RESOLVER, PHONE, 17, _udp(53, 50000, _dns_reply("img.example.com", "cdn.example.net", "2.22.237.73"))),
         "mDNSResponder"),
        (_ipv4(PHONE, "2.22.237.73", 6, _tcp(50004, 443, 0x02)), "App"),
        (_ipv4(PHONE, "93.184.216.34", 6, _tcp(50001, 443, 0x18, _client_hello("api.example.com"))), "App"),
    ])
    data = json.loads(json.dumps(kta.report(path, *kta.analyze(path))))
    app = next(a for a in data["apps"] if a["name"] == "App")
    assert data["packets"] == 3 and app["packets"] == 2
    assert app["hosts"] == [{"kind": "tls", "name": "api.example.com", "count": 1}]
    assert app["connections"] == [
        {"kind": "tcp", "ip": "2.22.237.73", "port": 443, "name": "img.example.com", "count": 1},
    ]


def test_incompatible_pymobiledevice3_exits_with_message():
    import types
    import pytest
    stub = types.SimpleNamespace(PcapdService=type("PcapdService", (), {}))
    with pytest.raises(SystemExit) as e:
        kta._check_pcapd(stub)
    assert "not compatible" in str(e.value) and "parse_device_packet" in str(e.value)


def _ipv6(src, dst, next_header, payload):
    """next_header names what follows the fixed header: TCP/UDP, or the first extension header in payload."""
    hdr = struct.pack(">IHBB16s16s", 6 << 28, len(payload), next_header, 64,
                      socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst))
    return b"\0" * 12 + b"\x86\xdd" + hdr + payload


PHONE6 = "2001:db8::20"
SERVER6 = "2606:4700::1"


def test_ipv6_extension_headers_are_followed(tmp_path):
    hop_by_hop = bytes([6, 0]) + b"\0" * 6                          # next: TCP, 8 bytes long
    first_fragment = bytes([6, 0]) + struct.pack(">HI", 0, 1)        # offset 0: TCP header inside
    later_fragment = bytes([6, 0]) + struct.pack(">HI", 8 << 3, 1)   # offset 64: only data
    path = _write(tmp_path, [
        (_ipv6(PHONE6, SERVER6, 0, hop_by_hop + _tcp(50000, 443, 0x18, _client_hello("hop.example.com"))), "App"),
        (_ipv6(PHONE6, SERVER6, 44, first_fragment + _tcp(50001, 443, 0x18, _client_hello("frag.example.com"))), "App"),
        (_ipv6(PHONE6, SERVER6, 44, later_fragment + b"\x16" * 60), "App"),
    ])
    _, _, hosts, ips, _ = kta.analyze(path)
    assert hosts["App"] == {"tls hop.example.com": 1, "tls frag.example.com": 1}
    assert not ips["App"]


def test_local_ipv6_is_skipped(tmp_path):
    path = _write(tmp_path, [
        (_ipv6(PHONE6, dst, 6, _tcp(50000, 443, 0x02)), "App")
        for dst in ("fc00::1", "fd12::1", "fe80::1", "febf::1", SERVER6)
    ])
    _, _, _, ips, _ = kta.analyze(path)
    assert list(ips["App"]) == [("tcp", SERVER6, ":443")]


def test_dns_over_tcp(tmp_path):
    query = _dns_query("tcp.example.com")
    reply = _dns_reply("tcp.example.com", "edge.example.net", "203.0.113.9")
    path = _write(tmp_path, [
        (_ipv4(PHONE, RESOLVER, 6, _tcp(50000, 53, 0x18, struct.pack(">H", len(query)) + query)), "App"),
        (_ipv4(RESOLVER, PHONE, 6, _tcp(53, 50000, 0x18, struct.pack(">H", len(reply)) + reply)), "App"),
    ])
    _, _, hosts, _, names = kta.analyze(path)
    assert hosts["App"] == {"dns tcp.example.com": 1}
    assert names == {"203.0.113.9": "tcp.example.com"}
