# SQLiBUSTER
SQLiBUSTER 🚀🔍
Welcome to SQLiBUSTER! 🎉 A powerful Python-based tool for discovering subdomains, checking live subdomains, enumerating URLs, and scanning for SQL injection vulnerabilities. It’s your all-in-one solution for web application security testing! 🛡️ Use responsibly and only on authorized systems! ⚠️
Features 🌟

Subdomain Enumeration 🔎: Find subdomains with tools like assetfinder, sublist3r, dnscan, findomain, subfinder, gobuster, and massdns.

DNS Validation ✅: Ensure subdomains resolve correctly via DNS checks.

Live Subdomain Checking 🌐: Identify live subdomains with HTTP status 200 using httpx.

URL Enumeration 🔗: Gather URLs from live subdomains with gau, waybackurls, and hakrawler.

SQL Injection Scanning 💉: Scan for SQL vulnerabilities using sqlmap, with pre-filtering by gf for efficiency.

Verbose Output 📢: Detailed progress and error logs for easy debugging.

File-Based Workflow 📁: Save and load results for seamless integration into other tools.


Prerequisites 🛠️
Before diving in, ensure you have the following ready:
System Dependencies

Python 3.8+ 🐍
Install required Python packages:pip install termcolor


Required tools (must be in PATH or specified paths):
assetfinder 🕵️‍♂️
sublist3r 🔍
dnscan 🌐
findomain 🚀
subfinder 🔎
gobuster 💥
massdns 📡
httpx 🌍
gau 🔗
waybackurls 📜
hakrawler 🕸️
sqlmap 💉
gf (with sqli.json in ~/.gf/) 📝



Configuration Files

A wordlist for subdomain enumeration (e.g., /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt) 📜
A resolver file for massdns (e.g., resolvers.txt with DNS resolvers) 🌐

Installation 📦

Clone the repo:git clone https://github.com/yourusername/SQLiBUSTER.git
cd SQLiBUSTER


Install Python dependencies:pip install -r requirements.txt


Install required tools:
On Linux (e.g., Kali), use package managers or tool-specific guides:sudo apt install assetfinder gobuster
go install github.com/hakluke/hakrawler@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
pip install sqlmap




Ensure sqli.json is in ~/.gf/ for gf filtering. Copy it from the gf tool’s pattern directory or create a custom one for SQLi patterns. 📝
Verify tools are in PATH:which assetfinder sublist3r dnscan findomain subfinder gobuster massdns httpx gau waybackurls hakrawler sqlmap gf



Usage 🎮
Run the full pipeline with main.py or use individual modules for specific tasks.
Full Pipeline
Edit main.py to configure your target:
domain = "example.com"  # Your target domain 🌐
wordlist = "/path/to/wordlist.txt"  # Subdomain wordlist 📜
resolvers = "resolvers.txt"  # DNS resolvers 🌍
subdomain_file = "subd.txt"  # Subdomain output 📁
alive_file = "alive_subdomains.txt"  # Live subdomains 📁
url_file = "urls.txt"  # URLs output 📁
sql_vuln_file = "sql_vulnerabilities.txt"  # SQL vuln output 📁
validate_dns = True  # Enable DNS validation ✅
verbose = True  # Enable verbose output 📢

Run:
python3 main.py

Individual Modules
Run each module with command-line arguments for flexibility.
Subdomain Enumeration (sub.py) 🔎
python3 sub.py -d example.com -o subdomains.txt -w /path/to/wordlist.txt -r resolvers.txt --validate-dns --verbose


-d: Target domain (required).
-o: Subdomain output file (default: subdomains.txt).
-w: Wordlist for gobuster and massdns.
-r: Resolver file for massdns.
--validate-dns: Validate DNS resolution.
--verbose: Show progress and errors.

Live Subdomain Checking (checkalive.py) 🌐
python3 checkalive.py -i subdomains.txt -o alive_subdomains.txt --verbose


-i: Input file with subdomains.
-o: Output file for live subdomains.
--verbose: Show progress and errors.

URL Enumeration (url.py) 🔗
python3 url.py -i alive_subdomains.txt -o urls.txt --verbose


-i: Input file with live subdomains.
-o: Output file for URLs.
--verbose: Show progress and errors.

SQL Injection Scanning (scan_sql_vulnerabilities.py) 💉
python3 scan_sql_vulnerabilities.py -i urls.txt -o sql_vulnerabilities.txt --verbose


-i: Input file with URLs.
-o: Output file for SQL vulnerability results.
--verbose: Show progress and errors.

Output 📄

Subdomains: Saved to subd.txt 📁
Live Subdomains: Saved to alive_subdomains.txt 🌐
URLs: Saved to urls.txt 🔗
SQL Vulnerabilities: Saved to sql_vulnerabilities.txt in JSON format 💉

Example sql_vulnerabilities.txt:
{
  "https://example.com/page?id=1": {
    "url": "https://example.com/page?id=1",
    "vulnerable": true,
    "details": {
      "parameter": "id",
      "dbms": "MySQL",
      "databases": ["db1", "db2"]
    }
  },
  "https://example.com/other": {
    "url": "https://example.com/other",
    "vulnerable": false,
    "details": {}
  }
}

Notes 📝

Performance ⚡: Uses ThreadPoolExecutor for parallel sqlmap scanning. Adjust max_workers in scan_sql_vulnerabilities.py for your system.
Temporary Files 🗑️: Automatically cleans up temp files (e.g., for massdns or httpx).
SQLMap Logs 💾: Stored in /dev/shm/sqlmap_logs to minimize disk I/O. Ensure sufficient RAM.
Ethical Use ⚖️: Only scan authorized targets. Unauthorized scanning is illegal!
Customization 🛠️: Modify tool paths (e.g., gf_path, sublist3r_path) if needed.

Troubleshooting 🐞

Tool Not Found: Verify tools are in PATH (which <tool>).
File Not Found: Check wordlist and resolver file paths.
Empty Output: Enable verbose mode to debug issues.
Permissions: Ensure write permissions for output files.
SQLMap Errors: Tweak sqlmap settings (e.g., --timeout, --threads) in scan_sql_vulnerabilities.py.

Contributing 🤝
We love contributions! 💖

Fork the repo.
Create a branch (git checkout -b feature/your-feature).
Commit changes (git commit -m "Add your feature").
Push (git push origin feature/your-feature).
Open a pull request.

License 📜
Licensed under the MIT License. See LICENSE for details.
Disclaimer ⚠️
SQLiBUSTER is for security researchers and authorized testers only. The authors are not liable for misuse or damage. Use ethically and responsibly! 🛡️
