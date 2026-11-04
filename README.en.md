```
    __   __
   / /__/ /_____ _
  / //_/ __/ __ `/
 / ,< / /_/ /_/ /
/_/|_|\__/\__,_/   v0.1.0

        iPhone traffic, cut by app
```

<p align="center">
  Capture an iPhone's traffic on a Mac over USB and see which app talks to which servers.
</p>

<p align="center"><a href="README.md">Русский</a> · English</p>

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

Record 60 seconds of traffic and show the result right away:

```bash
./kta run
```

Separate commands:

```bash
./kta capture --out phone.pcapng --seconds 30      # record only (without --seconds: until Ctrl+C)
./kta capture --out pin.pcapng --process Pinterest # one app only
./kta analyze phone.pcapng                          # analyze an existing file
./kta analyze phone.pcapng --process Pinterest
```

`--json` (for `analyze` and `run`) prints the full result as JSON, not cut to `--top`:

```bash
./kta analyze phone.pcapng --json > phone.json
```

For each app: `hosts` are names seen in DNS and TLS, `connections` are IP addresses with their port and the domain
a DNS answer gave for them (`name`, when known).

The ASCII banner goes to stderr. Turn it off with `./kta -s run` (`-s` goes before the command).

Sample output:

```
Pinterest  (2736 packets)
      1  tls api.pinterest.com
      1  tls i.pinimg.com
      4  dns graph.facebook.com
    163  quic 2.22.237.73  (i.pinimg.com)
```

`tls` is the server name from the TLS handshake, `dns` a DNS query, `quic` and `tcp` an IP address where no name
is visible. In brackets is the domain a DNS answer returned for that IP, if the answer was captured.

## In Wireshark

The process name is in the packet comment. Filter:

```
frame.comment contains "ProcName: Pinterest"
```

The comment holds `PID` and `ProcName` (the process), `EPID` and `EProcName` (the "effective" process; 4294967295
means unset) and `SVC` (the service class, QoS).

## Tests

The analyzer is tested without an iPhone:

```bash
python3 -m pytest -q tests
```

## Limitations

- **HTTPS is not decrypted.** You see domains and IPs, not the content of requests. For content you need a proxy
  (Proxyman, mitmproxy), which does not work with apps that use SSL pinning.
- **QUIC (HTTP/3)** encrypts the server name, so its domain comes from the DNS answer. If the address was cached
  before recording started or came through DNS-over-HTTPS, only the IP is shown.
- **A VPN on the iPhone hides traffic.** With a VPN on, apps show up inside the tunnel as an encrypted stream.
  Turn it off while capturing.
- The system does not attribute some packets to a process; they are listed as `(unattributed)`.
- Traffic between the Mac and the iPhone and other local IPv6 (`fc00::/7` and `fe80::/10`) is left out.

## How it works

1. The iPhone runs the diagnostic service `pcapd`, which sees packets on every network interface.
2. The Mac connects to it through lockdown over USB (the device has to trust the Mac).
3. Kta saves the stream as pcapng with the process metadata and reads DNS, TLS SNI and destination IPs from it.

Kta replaces the packet-reading method in `pymobiledevice3` to skip service frames that crash the capture with
`TruncatedDataError` on newer iOS versions.

## Intended use

Only for analyzing traffic on **your own** devices.
