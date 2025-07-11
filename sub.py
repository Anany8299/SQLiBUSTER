import subprocess
import os
import argparse
from typing import Set
import shutil
import socket
import re

def run_command(command: list, verbose: bool = False) -> Set[str]:
    try:
        env = os.environ.copy()
        env["PATH"] = f"/usr/bin:/usr/local/bin:{os.path.expanduser('~/bin')}:{env.get('PATH', '')}"
        result = subprocess.run(command, capture_output=True, text=True, check=True, env=env)
        return set(line.strip() for line in result.stdout.splitlines() if line.strip())
    except subprocess.CalledProcessError as e:
        if verbose:
            print(f"Error running {command[0]}: {e.stderr}")
        return set()
    except FileNotFoundError:
        if verbose:
            print(f"Error: {command[0]} not found in PATH. Ensure it is installed and accessible.")
        return set()

def clean_subdomains(subdomains: Set[str], domain: str) -> Set[str]:
    cleaned = set()
    pattern = re.compile(rf'^[a-zA-Z0-9][a-zA-Z0-9\-_\.]*\.{re.escape(domain)}$')
    noise_pattern = re.compile(r'^(?:Found:|\x1b\[\d*?[A-Za-z]|\[\S*?\]|\s+|\S+\s+)', re.MULTILINE)
    
    for sub in subdomains:
        cleaned_sub = noise_pattern.sub('', sub.strip())
        if cleaned_sub and pattern.match(cleaned_sub):
            cleaned.add(cleaned_sub)
    
    return cleaned

def validate_dns_subdomains(subdomains: Set[str], domain: str, verbose: bool = False) -> Set[str]:
    if verbose:
        print("Validating subdomains with DNS resolution...")
    valid_subdomains = set()
    
    for subdomain in subdomains:
        try:
            socket.getaddrinfo(subdomain, None, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            valid_subdomains.add(subdomain)
            if verbose:
                print(f"Valid subdomain: {subdomain}")
        except socket.gaierror:
            if verbose:
                print(f"Invalid subdomain (no DNS resolution): {subdomain}")
            continue
    
    return valid_subdomains

def read_subdomains_from_file(file_path: str, domain: str, verbose: bool = False) -> Set[str]:
    if not os.path.exists(file_path):
        if verbose:
            print(f"Error: Subdomain file {file_path} not found.")
        return set()
    
    with open(file_path, "r") as f:
        subdomains = set(line.strip() for line in f if line.strip())
    if verbose:
        print(f"Read {len(subdomains)} subdomains from {file_path}")
    return clean_subdomains(subdomains, domain)

def run_assetfinder(domain: str, verbose: bool = False) -> Set[str]:
    subdomains = run_command(["assetfinder", "--subs-only", domain], verbose)
    return clean_subdomains(subdomains, domain)

def run_sublister(domain: str, verbose: bool = False) -> Set[str]:
    try:
        temp_file = "sublister_temp.txt"
        if shutil.which("sublist3r"):
            run_command(["sublist3r", "-d", domain, "-o", temp_file], verbose)
        else:
            sublist3r_path = "/usr/bin/sublist3r"  # Adjusted per user
            if os.path.exists(sublist3r_path):
                run_command(["python3", sublist3r_path, "-d", domain, "-o", temp_file], verbose)
            else:
                if verbose:
                    print("Error: Sublist3r not found as 'sublist3r' or at expected path.")
                return set()
        subdomains = set()
        if os.path.exists(temp_file):
            with open(temp_file, "r") as f:
                subdomains = set(line.strip() for line in f if line.strip())
            os.remove(temp_file)
        return clean_subdomains(subdomains, domain)
    except Exception as e:
        if verbose:
            print(f"Error running Sublist3r: {e}")
        return set()

def run_dnscan(domain: str, verbose: bool = False) -> Set[str]:
    try:
        if shutil.which("dnscan"):
            subdomains = run_command(["dnscan", "-d", domain], verbose)
            return clean_subdomains(subdomains, domain)
        else:
            dnscan_path = "/usr/local/bin/dnscan.py"  # Adjusted per user
            if os.path.exists(dnscan_path):
                subdomains = run_command(["python3", dnscan_path, "-d", domain], verbose)
                return clean_subdomains(subdomains, domain)
            else:
                if verbose:
                    print("Error: DNScan not found as 'dnscan' or at expected path.")
                return set()
    except Exception as e:
        if verbose:
            print(f"Error running DNScan: {e}")
        return set()

def run_findomain(domain: str, verbose: bool = False) -> Set[str]:
    subdomains = run_command(["findomain", "-t", domain, "--quiet"], verbose)
    return clean_subdomains(subdomains, domain)

def run_subfinder(domain: str, verbose: bool = False) -> Set[str]:
    subdomains = run_command(["subfinder", "-d", domain, "-silent"], verbose)
    return clean_subdomains(subdomains, domain)

def run_gobuster(domain: str, wordlist: str, verbose: bool = False) -> Set[str]:
    subdomains = run_command(["gobuster", "dns", "-d", domain, "-w", wordlist, "-q"], verbose)
    return clean_subdomains(subdomains, domain)

def run_massdns(domain: str, wordlist: str, resolvers: str, verbose: bool = False) -> Set[str]:
    temp_subdomains_file = "subdomains_temp.txt"
    try:
        with open(wordlist, "r") as f:
            subdomains = [f"{line.strip()}.{domain}" for line in f if line.strip()]
        with open(temp_subdomains_file, "w") as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        result = run_command(["massdns", "-r", resolvers, "-q", "-t", "A", "-o", "S", temp_subdomains_file], verbose)
        valid_subdomains = set()
        for line in result:
            if line.endswith(". A"):
                subdomain = line.split()[0].rstrip(".")
                valid_subdomains.add(subdomain)
        return clean_subdomains(valid_subdomains, domain)
    except Exception as e:
        if verbose:
            print(f"Error running MassDNS: {e}")
        return set()
    finally:
        if os.path.exists(temp_subdomains_file):
            os.remove(temp_subdomains_file)

def enumerate_subdomains(domain: str, wordlist: str, resolvers: str, output_file: str, verbose: bool = False) -> Set[str]:
    if os.path.exists(output_file):
        if verbose:
            print(f"Subdomain file {output_file} exists. Skipping enumeration and reading from file.")
        return read_subdomains_from_file(output_file, domain, verbose)

    if verbose:
        print(f"Enumerating subdomains for {domain}...")
    all_subdomains = set()

    # Check if tools are installed
    tools = ["assetfinder", "sublist3r", "dnscan", "findomain", "subfinder", "gobuster", "massdns"]
    for tool in tools:
        if not shutil.which(tool):
            if verbose:
                print(f"Warning: {tool} not found in PATH. Trying fallback path for Sublist3r/DNScan if applicable.")

    # Run each tool and combine results
    if verbose:
        print("Running Assetfinder...")
    all_subdomains.update(run_assetfinder(domain, verbose))
    
    if verbose:
        print("Running Sublist3r...")
    all_subdomains.update(run_sublister(domain, verbose))
    
    if verbose:
        print("Running DNScan...")
    all_subdomains.update(run_dnscan(domain, verbose))
    
    if verbose:
        print("Running Findomain...")
    all_subdomains.update(run_findomain(domain, verbose))
    
    if verbose:
        print("Running Subfinder...")
    all_subdomains.update(run_subfinder(domain, verbose))
    
    if verbose:
        print("Running Gobuster...")
    all_subdomains.update(run_gobuster(domain, wordlist, verbose))
    
    if verbose:
        print("Running MassDNS...")
    all_subdomains.update(run_massdns(domain, wordlist, resolvers, verbose))

    # Save results to output file
    save_results(all_subdomains, output_file, verbose)
    return all_subdomains

def save_results(subdomains: Set[str], output_file: str, verbose: bool = False) -> None:
    with open(output_file, "w") as f:
        for subdomain in sorted(subdomains):
            f.write(f"{subdomain}\n")
    if verbose:
        print(f"Results saved to {output_file}")

def main():
    """Parse command-line arguments and run subdomain enumeration."""
    parser = argparse.ArgumentParser(description="Subdomain enumeration script using multiple tools.")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to enumerate subdomains for")
    parser.add_argument("-o", "--output", default="subdomains.txt", help="Output file for cleaned subdomains (default: subdomains.txt)")
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt", 
                        help="Wordlist for Gobuster and MassDNS (default: subdomains-top1million-5000.txt)")
    parser.add_argument("-r", "--resolvers", default="resolvers.txt", 
                        help="Resolver list for MassDNS (default: resolvers.txt)")
    parser.add_argument("--validate-dns", action="store_true", 
                        help="Validate subdomains with DNS resolution (optional)")
    parser.add_argument("--verbose", action="store_true", 
                        help="Print progress and error messages")
    args = parser.parse_args()

    # Validate inputs
    domain = args.domain.strip()
    if not domain:
        print("Error: Domain cannot be empty.")
        return
    if not os.path.exists(args.wordlist):
        print(f"Error: Wordlist file {args.wordlist} not found.")
        return
    if not os.path.exists(args.resolvers):
        print(f"Error: Resolver file {args.resolvers} not found.")
        return

    # Enumerate or read subdomains
    subdomains = enumerate_subdomains(domain, args.wordlist, args.resolvers, args.output, args.verbose)

    # Optionally validate DNS resolution
    if args.validate_dns:
        subdomains = validate_dns_subdomains(subdomains, domain, args.verbose)

    # Save cleaned subdomains
    save_results(subdomains, args.output, args.verbose)
    if args.verbose:
        print(f"Found {len(subdomains)} unique subdomains.")

if __name__ == "__main__":
    main()
