# Python TargetScan
No Nmap or external scanner commands. Python standard library performs TCP connect scans, banner detection, HTTP requests, TLS validation, FTP SYST and SMTP EHLO. ReportLab only formats PDFs.

## Kali / GitHub installation
```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python targetscan.py
```
No sudo needed. Enter an authorized IP/hostname without https://.
Default scans 33 common TCP ports. Choose broader coverage explicitly:
```bash
.venv/bin/python targetscan.py 192.168.56.101 --all-ports
.venv/bin/python targetscan.py 192.168.56.101 --ports 21,22,25,80,443,8080
```
Optional anonymous FTP login (no downloads or directory listings):
```bash
.venv/bin/python targetscan.py 192.168.56.101 --anonymous-ftp
```
PDF/JSON results go in reports/<timestamp>/; ports.json preserves individual states.
Use --address to choose one DNS-resolved IP. All traffic is pinned to that IP;
HTTP Host and TLS SNI preserve the hostname. HTTP redirects are recorded, never
followed. Default concurrency 40; --workers 1-100. Per socket operation timeout
is --timeout (default 2 seconds). Slow responses may be missed.

## Actual scope
TCP handshake confirms listening ports. Refused means closed; timeout/other
errors remain ambiguous. No ICMP discovery step: reachability comes from TCP.
HTTP/HTTPS on conventional web ports only; title, response headers, server hints.
TLS handshake records certificate validation/protocol/cipher. HTTP retrieval uses
unverified TLS after separately checking certificate validation so private lab
certificates can still be inspected; no authentication or credentials are sent.
SSH banner only, FTP greeting/SYST, SMTP greeting/EHLO. Other open ports remain
unknown if they don't send a recognizable banner. Website technology hints are
not a complete framework fingerprint. No UDP, OS fingerprinting, SMB/DNS protocol
enumeration, exploitation, brute force or vulnerability database. This version
is intentionally narrower than the earlier Nmap implementation. Banners do not
prove patch status. Findings currently cover failed TLS validation and anonymous
FTP acceptance; inventory evidence needs human review. No security score.
The report contains target details; keep it private. Actual reports are gitignored.

## Tests
```bash
.venv/bin/python -m unittest discover -s tests -v
```
Tests use local loopback servers; no external targets contacted.
"# systemscan" 
