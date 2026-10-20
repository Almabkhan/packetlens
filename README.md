# PacketLens

I built this after getting curious about what Wireshark is actually doing
under the hood. Instead of just using it, I wanted to build a smaller
version myself — something that reads a saved packet capture file and
figures out if anything shady happened in it.

So that's what PacketLens is: you give it a `.pcap` file, and it tells
you if it found a port scan, a password sent in plain text, someone
pulling off an ARP spoofing trick, or a DNS query that looks suspicious.
It only reads files you already have — it doesn't touch your network
card or sniff live traffic.

## What it looks for

**Port scans** — if one IP hits a bunch of different ports on another
machine really fast, that's basically the definition of a scan. I group
packets by source/destination pair and check the port count against a
time window.

**Passwords sent in the clear** — old protocols like FTP and Telnet
still send your username and password as plain text. If I see a `USER`
or `PASS` command on port 21, or an HTTP Basic Auth header, I pull it
out and show you exactly what was exposed.

**ARP spoofing** — this is the "two people claiming the same identity"
attack. I track which MAC address claims which IP over ARP, and if two
different MACs both claim the same IP, that's the signature of someone
trying to intercept traffic.

**Weird DNS lookups** — not a real threat-intel lookup (that needs
internet access, which this tool deliberately doesn't use), just some
honest heuristics: domains with sketchy keywords in them, or long
random-looking subdomains that look machine-generated rather than typed
by a person.

## Setting it up

```bash
git clone https://github.com/Almabkhan/packetlens
cd packetlens
pip install -r requirements.txt
```

## Trying it out

I included a script that generates some test captures from scratch —
no real traffic involved, just packets I built in code so I'd have
something safe to test against:

```bash
python samples/generate_samples.py
python main.py samples/port_scan.pcap
```

That should print something like this:

```text
======================================================================
  PACKETLENS — Analyzing: samples/plaintext_creds.pcap
======================================================================

  Total packets   : 3
  Findings        : 2
  Risk            : High (50/100)
  Reports saved to: ./scan_output/

  [CRITICAL] plaintext_credential
    FTP password sent in cleartext
```

It also writes a JSON and an HTML report into `scan_output/` so you
don't just have to read terminal output.

## Running your own capture against it

Any real `.pcap` file works the same way:

```bash
python main.py path/to/your/capture.pcap
```

## The tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

There are 14 of them, and they actually run against the generated test
captures — not fake/mocked data. I also specifically tested that normal,
boring traffic doesn't get flagged as anything, because a tool that
cries wolf on everything isn't useful.

## How it's organized

```text
packetlens/
├── main.py                 # ties everything together, the CLI
├── core/
│   └── pcap_parser.py        # reads the pcap, turns packets into plain dicts
├── analyzers/
│   ├── port_scan_detector.py
│   ├── credential_leak_detector.py
│   ├── arp_spoof_detector.py
│   └── dns_analyzer.py
├── reports/
│   └── generator.py          # scores the findings, writes JSON/HTML
├── samples/
│   └── generate_samples.py   # builds the test pcap files
├── tests/
│   └── test_analyzers.py
└── requirements.txt
```

Each analyzer only does one thing and doesn't know about the others —
easier to test, easier to add a new one later without breaking what's
already there.

## Where this falls short (being honest about it)

- It only reads files. No live sniffing. That's on purpose, but worth
  saying clearly.
- The DNS check is just pattern-matching, not a real "is this domain
  actually malicious" lookup. A genuinely malicious domain with a
  normal-sounding name would slip right past it.
- The port scan detector uses fixed numbers (how many ports, how fast).
  A patient attacker scanning one port every few hours wouldn't trip it.
- It can only catch credentials that were never encrypted in the first
  place. If something's using TLS, you won't see the password here —
  which is exactly what TLS is supposed to do.

## Ideas for later

- Let the port-scan thresholds be set from the command line instead of
  hardcoded
- Pull out TLS certificate info and flag ones that are expired or about
  to be
- Maybe a simple timeline view of the capture instead of just a flat
  list of findings
