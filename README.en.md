```
    __   __
   / /__/ /_____ _
  / //_/ __/ __ `/
 / ,< / /_/ /_/ /
/_/|_|\__/\__,_/   v0.1.0

        iPhone traffic, cut by app
```

<p align="center">
  Capture an iPhone's traffic on a Mac over USB and see which app talks to which servers.<br>
  <a href="README.md">Русский</a>
</p>

---

## What it is

Kta records an iPhone's traffic over USB (the phone's `pcapd` service, through
[pymobiledevice3](https://github.com/doronz88/pymobiledevice3)) and lists the domains and IP addresses of each app.

Unlike `rvictl`, every packet is saved **with the name and PID of its process**. The `.pcapng` file opens in
Wireshark.

Tested on iOS 27 and macOS 27; older versions have not been tried.

## Install

You need macOS, Python 3 and an iPhone on a cable.

```bash
git clone https://github.com/infarmor/Kta.git
cd Kta
./install.sh
```

Connect the iPhone, unlock it and tap "Trust".

## Use

Record 60 seconds of traffic and show the result straight away:

```bash
./kta run
```

Separate commands:

```bash
./kta capture --out phone.pcapng --seconds 30      # record only (without --seconds: until Ctrl+C)
./kta capture --out pin.pcapng --process Pinterest # one app only
./kta analyze phone.pcapng                          # read a saved file
./kta analyze phone.pcapng --process Pinterest
./kta analyze phone.pcapng --json > phone.json      # result as JSON (every line unless --top is given)
./kta analyze phone.pcapng --top 30                 # how many apps and lines to show (default 12)
```

The ASCII banner goes to stderr. Turn it off with `./kta -s run` (`-s` goes before the command).

Sample output:

```
Pinterest  (2736 packets)
      1  tls api.pinterest.com
      1  tls i.pinimg.com
      4  dns graph.facebook.com
    163  quic i.pinimg.com (2.22.237.73)
```

`tls` and `quic` followed by a name: the server name from the handshake (TLS, or the first QUIC packet).
`dns`: a DNS query made by the app itself. Lines with an IP address count QUIC packets and new TCP connections;
their name comes from that app's own handshake or from DNS answers in the capture, and when neither has it, only
the address is shown.

iOS usually resolves names for apps in the system process `mDNSResponder`, so its DNS answers are always read,
even with `analyze --process`. `capture --process`, however, records only one app's packets, without
`mDNSResponder`: names for IP addresses then come from handshakes alone.

## In Wireshark

The process name is in the packet comment. Filter:

```
frame.comment contains "ProcName: Pinterest"
```

In the comment: `PID` and `ProcName` are the process, `EPID` and `EProcName` the "effective" process
(4294967295 means "not set"), `SVC` the service class (QoS).

## Limits

- **HTTPS is not decrypted.** You see domains and IPs, not the content of requests. For content you need a
  proxy (Proxyman, mitmproxy), and that does not work with apps that pin their certificates.
- **QUIC (HTTP/3).** The server name is read from the connection's first packet (its keys are public, RFC 9001).
  If that packet is not in the capture (the connection was opened before recording started), only the IP or a
  name from DNS is shown.
- **A VPN on the iPhone hides the traffic.** With a VPN on, apps appear inside the tunnel as one encrypted
  stream. Turn it off while capturing.
- Some packets are not tied to a process by the system; they are shown as `(unattributed)`.
- Traffic between the Mac and the iPhone themselves (private `fd..` addresses) is left out of the analysis.

## How it works

1. The diagnostic service `pcapd` on the iPhone sees packets on every network interface.
2. The Mac connects to it through lockdown over USB (the device has to trust the Mac).
3. Kta saves the stream as pcapng with the process metadata and reads DNS queries and answers, the server name
   from TLS and QUIC (SNI) and the destination IP addresses. A handshake split over several TCP segments or QUIC
   packets is put back together. The file is read block by block, so long captures are not loaded into memory
   at once.

Kta replaces the packet reader of `pymobiledevice3` so that it skips the service frames that make captures fail
with `TruncatedDataError` on recent iOS versions.

## Tests

```bash
.venv/bin/python -m unittest discover tests
```

## Intended use

Only for analysing traffic on **your own** devices.
