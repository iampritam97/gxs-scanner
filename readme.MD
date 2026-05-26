# GXS Scanner

Deep vulnerability scanner for XXE, GraphQL, and SSTI.

## Install
````bash
go install github.com/iampritam97/gxs-scanner@latest
````

## Usage
````bash
gxs-scanner -urls targets.txt -oob your.burpcollaborator.net
````

## Features
- XXE: in-band, OOB, blind, time-based
- GraphQL: introspection, IDOR, SQLi, batch
- SSTI: 15+ engines, RCE detection

---

### .gitignore for Go

````
# Binaries
gxs-scanner
*.exe

# Output
findings.json
*.txt

# Go
vendor/
````

---

### Quick Checklist

| Step | Command |
|---|---|
| Init module | `go mod init github.com/iampritam97/gxs-scanner` |
| Commit | `git commit -m "v1.0.0"` |
| Tag | `git tag v1.0.0 && git push origin v1.0.0` |
| Verify | Visit `pkg.go.dev/github.com/iampritam97/gxs-scanner` |
| Install test | `go install github.com/iampritam97/gxs-scanner@latest` |
