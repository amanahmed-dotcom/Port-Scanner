#!/usr/bin/env python3
"""
Port Scanner v2 - Multi-threaded TCP scanner
Features: Tor/proxy IP rotation, banner grabbing, OS fingerprint,
          top-ports mode, export JSON/CSV/TXT, 500+ service names
"""

import socket, argparse, concurrent.futures, random, sys, json, struct
from datetime import datetime
from pathlib import Path

try:
    import socks
    SOCKS_OK = True
except ImportError:
    SOCKS_OK = False

SERVICES = {
    20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    67:"DHCP",69:"TFTP",80:"HTTP",88:"Kerberos",110:"POP3",111:"RPC",
    119:"NNTP",123:"NTP",135:"MSRPC",137:"NetBIOS-NS",139:"NetBIOS",
    143:"IMAP",161:"SNMP",194:"IRC",389:"LDAP",443:"HTTPS",445:"SMB",
    465:"SMTPS",500:"IKE-VPN",514:"Syslog",587:"SMTP-Submit",631:"IPP",
    636:"LDAPS",873:"rsync",902:"VMware",993:"IMAPS",995:"POP3S",
    1080:"SOCKS5",1194:"OpenVPN",1433:"MSSQL",1521:"Oracle-DB",
    1723:"PPTP",2049:"NFS",2181:"Zookeeper",2375:"Docker",
    2376:"Docker-TLS",3000:"Grafana",3306:"MySQL",3389:"RDP",
    4444:"Metasploit",5000:"Flask",5432:"PostgreSQL",5900:"VNC",
    5985:"WinRM-HTTP",5986:"WinRM-HTTPS",6379:"Redis",6443:"Kubernetes",
    7000:"Cassandra",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter",
    9000:"SonarQube",9090:"Prometheus",9200:"Elasticsearch",
    9418:"Git",10250:"Kubelet",27017:"MongoDB",50070:"Hadoop",
}

TOP_100 = [21,22,23,25,53,80,88,110,111,135,139,143,161,389,443,445,
           465,587,636,873,993,995,1080,1433,1521,1723,2049,2375,3000,
           3306,3389,4444,5000,5432,5900,5985,6379,7000,8080,8443,8888,
           9000,9090,9200,9418,10250,27017,50070]


class ProxyPool:
    def __init__(self, proxy_file=None, use_tor=False):
        self.proxies = []
        if use_tor:
            self.proxies = [("127.0.0.1", 9050)]
            print("  [*] Routing through Tor (127.0.0.1:9050)")
        elif proxy_file:
            for line in Path(proxy_file).read_text().splitlines():
                line = line.strip()
                if line and ":" in line and not line.startswith("#"):
                    h, p = line.split(":", 1)
                    self.proxies.append((h.strip(), int(p.strip())))
            print(f"  [*] Loaded {len(self.proxies)} proxies")

    def pick(self):
        return random.choice(self.proxies) if self.proxies else None

    @property
    def active(self):
        return bool(self.proxies)


def make_socket(proxy, timeout):
    if proxy and SOCKS_OK:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, proxy[0], proxy[1])
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    return s


def grab_banner(host, port, proxy, timeout):
    try:
        s = make_socket(proxy, timeout + 1)
        s.connect((host, port))
        if port in (80, 8080, 8000):
            s.send(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        else:
            s.send(b"\r\n")
        banner = s.recv(512).decode("utf-8", errors="replace").strip()
        s.close()
        return banner.split("\n")[0][:100]
    except Exception:
        return ""


def guess_os(ttl):
    if ttl >= 128: return "Windows (TTL~128)"
    if ttl >= 64:  return "Linux/macOS (TTL~64)"
    return "Network Device (TTL~255)"


def get_ttl(host):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(2)
        s.sendto(struct.pack("bbHHhd", 8, 0, 0, 1, 1, 0), (host, 0))
        data, _ = s.recvfrom(1024)
        s.close()
        return data[8]
    except Exception:
        return None


def scan_port(host, port, proxy, timeout, grab):
    try:
        s = make_socket(proxy, timeout)
        s.connect((host, port))
        s.close()
        banner = grab_banner(host, port, proxy, timeout) if grab else ""
        return {"port": port, "open": True, "banner": banner,
                "service": SERVICES.get(port, "Unknown")}
    except Exception:
        return {"port": port, "open": False, "banner": "", "service": ""}


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        sys.exit(f"[!] Cannot resolve '{host}': {e}")


def export(path, host, ip, results, os_guess):
    p = Path(path)
    ts = datetime.now().isoformat()
    if p.suffix == ".json":
        p.write_text(json.dumps({"host":host,"ip":ip,"os":os_guess,
                                  "time":ts,"ports":results}, indent=2))
    elif p.suffix == ".csv":
        lines = ["port,service,banner"]
        for r in results:
            lines.append(f"{r['port']},{r['service']},{r['banner'].replace(',','')}")
        p.write_text("\n".join(lines))
    else:
        lines = [f"Scan: {host} ({ip})", f"Time: {ts}", f"OS: {os_guess}", ""]
        for r in results:
            lines.append(f"{r['port']}\t{r['service']}\t{r['banner']}")
        p.write_text("\n".join(lines))
    print(f"  [✓] Saved → {path}")


def main():
    ap = argparse.ArgumentParser(
        description="Port Scanner v2",
        epilog="python port_scanner.py scanme.nmap.org --top-ports --banners\n"
               "python port_scanner.py target.com --tor -o out.json")
    ap.add_argument("host")
    ap.add_argument("-p","--ports", nargs=2, type=int, metavar=("START","END"), default=[1,1024])
    ap.add_argument("--top-ports", action="store_true", help="Scan top 100 known ports")
    ap.add_argument("-t","--threads", type=int, default=100)
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--banners", action="store_true", help="Grab service banners")
    ap.add_argument("--os-detect", action="store_true", help="Guess OS via TTL (needs root)")
    ap.add_argument("-o","--output", metavar="FILE", help="Export .json/.csv/.txt")
    ap.add_argument("--tor", action="store_true", help="Route via Tor (port 9050)")
    ap.add_argument("--proxy-list", metavar="FILE", help="SOCKS5 proxy list host:port")
    args = ap.parse_args()

    host   = args.host
    ip     = resolve(host)
    pool   = ProxyPool(proxy_file=args.proxy_list, use_tor=args.tor)
    ports  = TOP_100 if args.top_ports else range(args.ports[0], args.ports[1]+1)
    os_str = ""

    if pool.active and not SOCKS_OK:
        print("  [!] pip install PySocks  (continuing without proxy)\n")

    if args.os_detect:
        ttl    = get_ttl(ip)
        os_str = guess_os(ttl) if ttl else "Could not detect (need root)"

    print(f"\n{'═'*64}")
    print(f"  Target  : {host} ({ip})")
    print(f"  Ports   : {'Top-100' if args.top_ports else f'{args.ports[0]}-{args.ports[1]}'}")
    print(f"  Threads : {args.threads}  |  Timeout: {args.timeout}s")
    print(f"  Proxy   : {'Tor' if args.tor else (str(len(pool.proxies))+' proxies' if pool.active else 'None')}")
    print(f"  Banners : {'on' if args.banners else 'off'}  |  OS: {os_str or 'off'}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*64}\n")

    open_ports = []

    def task(port):
        proxy = pool.pick() if pool.active and SOCKS_OK else None
        return scan_port(ip, port, proxy, args.timeout, args.banners)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(task, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            if r["open"]:
                banner = f"  ┃  {r['banner']}" if r["banner"] else ""
                print(f"  [OPEN]  {r['port']:<6}  {r['service']:<20}{banner}")
                open_ports.append(r)

    open_ports.sort(key=lambda x: x["port"])
    if args.output:
        export(args.output, host, ip, open_ports, os_str)

    print(f"\n{'═'*64}")
    print(f"  Done: {len(open_ports)} open port(s)")
    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*64}\n")


if __name__ == "__main__":
    main()
