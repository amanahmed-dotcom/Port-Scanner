# Port Scanner v2

Multi-threaded TCP scanner — Tor/proxy IP rotation, banner grabbing, OS detection, export support.

## Install
```bash
pip install PySocks    # only needed for --tor / --proxy-list
```

## Run
```bash
python port_scanner.py scanme.nmap.org
python port_scanner.py 10.0.0.1 --top-ports --banners
python port_scanner.py target.com --tor -o results.json
sudo python port_scanner.py target.com --os-detect
python port_scanner.py target.com -p 1 65535 -t 200 -o out.csv
```

## All flags
| Flag | What it does |
|------|--------------|
| `-p START END` | Port range (default 1-1024) |
| `--top-ports` | Scan top 100 common ports only |
| `-t N` | Thread count (default 100) |
| `--timeout N` | Seconds per connection |
| `--banners` | Read service banner from open ports |
| `--os-detect` | Guess OS from TTL (needs sudo) |
| `--tor` | Route all connections through Tor |
| `--proxy-list FILE` | Rotate through SOCKS5 proxy list |
| `-o FILE` | Export results (.json / .csv / .txt) |
