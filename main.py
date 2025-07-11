import os
from sub import enumerate_subdomains, validate_dns_subdomains, save_results
from checkalive import run_httpx
from url import enumerate_urls
from scan_sql_vulnerabilities import scan_sql_vulnerabilities
from termcolor import colored


def print_banner():
    """Print the SQLiBUSTER banner."""
    banner = """ 
   ▄████████ ████████▄    ▄█        ▄█  ▀█████████▄  ███    █▄     ▄████████     ███        ▄████████    ▄████████ 
  ███    ███ ███    ███  ███       ███    ███    ███ ███    ███   ███    ███ ▀█████████▄   ███    ███   ███    ███ 
  ███    █▀  ███    ███  ███       ███▌   ███    ███ ███    ███   ███    █▀     ▀███▀▀██   ███    █▀    ███    ███ 
  ███        ███    ███  ███       ███▌  ▄███▄▄▄██▀  ███    ███   ███            ███   ▀  ▄███▄▄▄      ▄███▄▄▄▄██▀ 
▀███████████ ███    ███  ███       ███▌ ▀▀███▀▀▀██▄  ███    ███ ▀███████████     ███     ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   
         ███ ███    ███  ███       ███    ███    ██▄ ███    ███          ███     ███       ███    █▄  ▀███████████ 
   ▄█    ███ ███  ▀ ███  ███▌    ▄ ███    ███    ███ ███    ███    ▄█    ███     ███       ███    ███   ███    ███ 
 ▄████████▀   ▀██████▀▄█ █████▄▄██ █▀   ▄█████████▀  ████████▀   ▄████████▀     ▄████▀     ██████████   ███    ███ 
                         ▀                                                                              ███    ███ 
                                                                                        
    """
    print(colored(banner, "red"))
    print(colored("SQL Injection Vulnerability Scanner", "cyan"))
    print(colored("Use responsibly on authorized systems only!", "yellow"))
    print()

def main():
    """Main function to run the vulnerability scanning pipeline."""
    # Configuration
    domain = "Domain name for scanning"
    wordlist = "Put your wordlist directory here"
    resolvers = "resolvers.txt"
    subdomain_file = "subd.txt"
    alive_file = "alive_subdomains.txt"
    url_file = "urls.txt"
    sql_vuln_file = "sql_vulnerabilities.txt"
    validate_dns = True
    verbose = True

    print_banner()

    # Print current working directory for debugging
    if verbose:
        print(colored(f"Current working directory: {os.getcwd()}", "cyan"))

    # Validate file paths
    if not os.path.exists(wordlist):
        print(colored(f"Error: Wordlist file {wordlist} not found.", "yellow"))
        return
    if not os.path.exists(resolvers):
        print(colored(f"Error: Resolver file {resolvers} not found.", "yellow"))
        return
    if subdomain_file == alive_file or subdomain_file == url_file or alive_file == url_file or url_file == sql_vuln_file:
        print(colored("Error: Input and output files must be distinct.", "yellow"))
        return

    # Enumerate or read subdomains
    if verbose:
        print(colored(f"Enumerating subdomains for {domain}...", "cyan"))
    try:
        subdomains = enumerate_subdomains(domain, wordlist, resolvers, subdomain_file, verbose)
        if verbose:
            print(colored(f"Found {len(subdomains)} unique subdomains.", "green"))
    except Exception as e:
        print(colored(f"Error in subdomain enumeration: {e}", "yellow"))
        return

    # Optionally validate DNS
    if validate_dns:
        if verbose:
            print(colored("Validating DNS for subdomains...", "cyan"))
        try:
            subdomains = validate_dns_subdomains(subdomains, domain, verbose)
            if verbose:
                print(colored(f"Found {len(subdomains)} valid subdomains after DNS validation.", "green"))
        except Exception as e:
            print(colored(f"Error in DNS validation: {e}", "yellow"))
            return

    # Save subdomains
    try:
        save_results(subdomains, subdomain_file, verbose)
        if verbose:
            print(colored(f"Subdomains saved to {subdomain_file}", "green"))
    except Exception as e:
        print(colored(f"Error saving subdomains: {e}", "yellow"))
        return

    # Check alive subdomains with httpx or read from existing file
    if verbose:
        print(colored("Checking alive subdomains...", "cyan"))
    try:
        alive_subdomains = run_httpx(subdomains, input_file=subdomain_file, output_file=alive_file, verbose=verbose)
        if verbose:
            print(colored(f"Found {len(alive_subdomains)} alive subdomains with status code 200.", "green"))
    except Exception as e:
        print(colored(f"Error in checking alive subdomains: {e}", "yellow"))
        return

    # Enumerate or read URLs from alive subdomains
    if verbose:
        print(colored("Enumerating URLs...", "cyan"))
    try:
        urls = enumerate_urls(input_file=alive_file, output_file=url_file, verbose=verbose)
        if verbose:
            print(colored(f"Found {len(urls)} unique URLs.", "green"))
            # Debug URLs content
            if os.path.exists(url_file):
                with open(url_file, "r") as f:
                    sample_urls = [line.strip() for line in f.readlines()[:5] if line.strip()]
                print(colored(f"Sample URLs from {url_file}:\n{chr(10).join(sample_urls)}", "green"))
            else:
                print(colored(f"Error: {url_file} not found after enumeration.", "yellow"))
    except Exception as e:
        print(colored(f"Error in URL enumeration: {e}", "yellow"))
        return

    # Verify urls.txt permissions and content before SQL scanning
    if not os.path.exists(url_file):
        print(colored(f"Error: {url_file} does not exist for SQL scanning.", "yellow"))
        return
    if not os.access(url_file, os.R_OK):
        print(colored(f"Error: No read permission for {url_file}.", "yellow"))
        return
    if os.path.getsize(url_file) == 0:
        print(colored(f"Error: {url_file} is empty.", "yellow"))
        return

    # Scan URLs for SQL injection vulnerabilities
    if verbose:
        print(colored("Scanning for SQL vulnerabilities...", "cyan"))
    try:
        sql_results = scan_sql_vulnerabilities(input_file=url_file, output_file=sql_vuln_file, verbose=verbose)
        vulnerable_count = sum(1 for r in sql_results.values() if r["vulnerable"])
        print(colored(f"Found {vulnerable_count} URLs with potential SQL injection vulnerabilities.", "cyan"))
    except Exception as e:
        print(colored(f"Error in SQL scanning: {e}", "yellow"))
        return

    if verbose:
        print(colored("Pipeline completed successfully!", "green"))

if __name__ == "__main__":
    main()
