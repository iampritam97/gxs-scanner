# GXS Scanner v2.0

> Deep single-vulnerability scanner for bug bounty hunters.  
> **XXE | GraphQL | SSTI | SSRF | Log4Shell | Prototype Pollution**

```
 ██████╗ ██╗  ██╗███████╗    ██╗   ██╗██████╗      ██████╗
██╔════╝ ╚██╗██╔╝██╔════╝    ██║   ██║╚════██╗    ██╔═████╗
██║  ███╗ ╚███╔╝ ███████╗    ██║   ██║ █████╔╝    ██║██╔██║
██║   ██║ ██╔██╗ ╚════██║    ╚██╗ ██╔╝██╔═══╝     ████╔╝██║
╚██████╔╝██╔╝ ██╗███████║     ╚████╔╝ ███████╗    ╚██████╔╝
 ╚═════╝ ╚═╝  ╚═╝╚══════╝     ╚═══╝  ╚══════╝     ╚═════╝
```

---

## Install

```bash
go install github.com/iampritam97/gxs-scanner@latest
```

Or build from source:

```bash
git clone https://github.com/iampritam97/gxs-scanner
cd gxs-scanner
go build -ldflags="-s -w" -o gxs-scanner .
```

---

## Quick Start

```bash
# Scan a single URL
gxs-scanner -u "https://target.com/api?q=test"

# Scan a list of URLs
gxs-scanner -urls targets.txt

# Read from stdin (pipe from other tools)
cat urls.txt | gxs-scanner -urls -

# With OOB (Burp Collaborator or interactsh)
gxs-scanner -urls targets.txt -oob your.burpcollaborator.net

# Self-hosted OOB listener
gxs-scanner -urls targets.txt -self-oob -oob-port 8888

# With auth + proxy (route through Burp)
gxs-scanner -urls targets.txt -auth "Bearer TOKEN" -cookie "session=abc" -proxy http://127.0.0.1:8080

# WAF bypass mode
gxs-scanner -urls targets.txt -waf-bypass -rotate-ua -random-xff

# Only specific modules
gxs-scanner -urls targets.txt -xxe=false -gql=true -ssti=true -ssrf=false -log4j=false -proto=false

# Full output with markdown report
gxs-scanner -urls targets.txt -oob host.com -o findings.json -md report.md -v
```

---

## All Flags

### Input
| Flag | Default | Description |
|------|---------|-------------|
| `-u` | | Single target URL |
| `-urls` | `-` | File of URLs (one per line), `-` for stdin |

### Auth
| Flag | Default | Description |
|------|---------|-------------|
| `-auth` | | Authorization header (e.g. `Bearer TOKEN`) |
| `-cookie` | | Cookie header value |
| `-H` | | Custom header, repeatable (e.g. `-H "X-Api-Key: abc"`) |

### Network
| Flag | Default | Description |
|------|---------|-------------|
| `-proxy` | | HTTP proxy (e.g. `http://127.0.0.1:8080`) |
| `-workers` | `5` | Concurrent goroutines |
| `-timeout` | `15` | HTTP timeout in seconds |
| `-delay` | `0` | Delay between requests per target (ms) |
| `-retries` | `2` | Retries on network error with backoff |
| `-max-body` | `512` | Max response body size in KB |

### OOB
| Flag | Default | Description |
|------|---------|-------------|
| `-oob` | | External OOB host (Burp Collaborator, interactsh) |
| `-oob-port` | `8888` | Local OOB listener port |
| `-self-oob` | `false` | Start built-in OOB HTTP server |

### Modules
| Flag | Default | Description |
|------|---------|-------------|
| `-xxe` | `true` | XXE scanner |
| `-gql` | `true` | GraphQL scanner |
| `-ssti` | `true` | SSTI scanner |
| `-ssrf` | `true` | SSRF scanner |
| `-log4j` | `true` | Log4Shell scanner |
| `-proto` | `true` | Prototype Pollution scanner |

### Output
| Flag | Default | Description |
|------|---------|-------------|
| `-o` | `findings.json` | JSON report output path |
| `-md` | | Markdown report output path |
| `-v` | `false` | Verbose: print every request |
| `-silent` | `false` | Silent: only print findings |
| `-resume` | `.gxs_resume` | Checkpoint file path |
| `-no-resume` | `false` | Ignore existing checkpoint |

### Evasion
| Flag | Default | Description |
|------|---------|-------------|
| `-waf-bypass` | `false` | Enable WAF evasion encodings |
| `-rotate-ua` | `true` | Rotate User-Agent strings |
| `-random-xff` | `false` | Randomize X-Forwarded-For |

---

## Module Details

### 🔴 XXE
- In-band file read: `/etc/passwd`, `/etc/shadow`, Windows hosts/win.ini
- PHP filter wrapper (base64 exfil)
- SSRF via XXE (AWS IMDSv1, GCP metadata)
- Error-based parameter entity exfiltration
- SOAP envelope wrapping
- SVG file upload XXE
- Multipart/form-data XML upload
- Out-of-Band (HTTP entity callback)
- OOB parameter entity
- Blind time-based (non-routable IP delay)
- Content-types: `application/xml`, `text/xml`, `application/soap+xml`, `image/svg+xml`

### 🟣 GraphQL
- Endpoint auto-discovery (13 common paths)
- Introspection via POST + GET
- Sensitive type schema probe (`User`, `Admin`, `Token`, `Secret`...)
- Field suggestion / debug mode detection
- Batch query attack (rate-limit bypass)
- Alias overloading DoS
- SQL injection via query arguments
- IDOR user/account enumeration (IDs 1–5)
- Mutation fuzzing (mass assignment, privilege escalation)
- Auth bypass — sensitive queries without token
- SSRF via GraphQL URL arguments (OOB)
- Persisted query abuse (APQ)

### 🟡 SSTI
- 20+ engine probes: Jinja2, Twig, Freemarker, ERB, Smarty, Velocity, OGNL, Thymeleaf, Spring SPEL, Mako, Tornado, Pebble, Handlebars, Slim
- RCE probes per engine (`id` command output)
- False positive filtering via baseline comparison
- Injection vectors: GET params, POST form, POST JSON, HTTP headers
- Header injection: `User-Agent`, `Referer`, `X-Forwarded-For`, `Accept-Language`
- Blind time-based per engine (sleep payloads)
- OOB RCE via curl callback

### 🟠 SSRF
- In-band GET/POST/JSON across common URL param names (50+)
- Cloud metadata: AWS IMDSv1/IAM, GCP, Azure, Alibaba
- Internal service detection: Redis, Elasticsearch, MongoDB, Consul, localhost
- HTTP header injection: `X-Forwarded-For`, `X-Original-URL`, `True-Client-IP`...
- Scheme injection: `file://`, `dict://`, `gopher://`
- IP bypass variants: hex, decimal, IPv6 mapped, @ notation
- OOB blind SSRF via URL params + headers
- Blind time-based (non-routable internal IPs)
- Open redirect detection (bonus)

### 🔵 Log4Shell (CVE-2021-44228)
- 14 payload variants: classic, obfuscated `${lower:}`, `${upper:}`, nested, unicode
- Covers CVE-2021-44228, CVE-2021-45046
- Injection into 22 HTTP headers
- Injection into URL params, JSON body, form body
- OOB JNDI callback detection (LDAP, LDAPS, RMI, DNS)
- Requires `-oob` flag

### 🟢 Prototype Pollution
- JSON body: `__proto__`, `constructor.prototype`, nested, array
- Query string: `__proto__[key]=val`, `constructor[prototype][key]=val`
- HTTP methods: POST, PUT, PATCH, merge-patch
- Path-based: `/__proto__/`, `/constructor/prototype/`
- Status code oracle (behavioral change detection)
- Server-side privilege escalation oracle (admin path probe after pollution)

---

## Detection Methods

| Method | Description |
|--------|-------------|
| **In-band** | Pattern matching in HTTP response body |
| **Out-of-Band** | External callback (HTTP/JNDI/DNS) |
| **Blind Time-based** | Response delay from internal connections |
| **Error-based** | DB/engine error messages in response |
| **Status Oracle** | HTTP status code change after payload |
| **Baseline diff** | Response compared to clean request (reduces false positives) |

---

## Output

### JSON (`-o findings.json`)
```json
[
  {
    "url": "https://target.com/api",
    "vulnerability": "XXE",
    "type": "In-band File Read (application/xml)",
    "payload": "Linux passwd",
    "evidence": "Pattern 'root:.*:0:0:' matched",
    "severity": "CRITICAL",
    "cvss_score": 9.0,
    "timestamp": "2026-05-27T10:00:00Z",
    "request": "POST /api\nContent-Type: application/xml\n\n...",
    "response_snippet": "root:x:0:0:root:/root:/bin/bash"
  }
]
```

### Markdown (`-md report.md`)
Ready to paste into HackerOne / Bugcrowd reports. Includes severity table, per-finding payload/evidence/request blocks, and CVSS scores.

---

## Combine with Other Tools

```bash
# Feed subfinder + httpx into gxs
subfinder -d target.com -silent | httpx -silent | gxs-scanner -urls -

# Waybackurls + filter params + scan
waybackurls target.com | grep "=" | gxs-scanner -urls - -ssti=true -ssrf=true

# Nuclei for recon, gxs for deep dive
nuclei -l targets.txt -t exposures/ -silent | grep "url" | gxs-scanner -urls -
```

---

## Resume

If a scan is interrupted, progress is saved to `.gxs_resume`.  
Re-running with the same command resumes from where it left off.  
Use `-no-resume` to force a fresh scan.

---

## Disclaimer

> For authorized security testing only. Only scan targets you have explicit written permission to test. The authors are not responsible for misuse.

---

## License

MIT © 2026 iampritam97