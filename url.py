import subprocess
import os
import shutil
import argparse
from typing import Set
from termcolor import colored

def run_command(command: list, verbose: bool = False) -> Set[str]:
    try:
        env = os.environ.copy()
        env["PATH"] = f"/usr/bin:/usr/local/bin:{os.path.expanduser('~/bin')}:{env.get('PATH', '')}"
        result = subprocess.run(command, capture_output=True, text=True, check=True, env=env)
        return set(line.strip() for line in result.stdout.splitlines() if line.strip())
    except subprocess.CalledProcessError as e:
        if verbose:
            print(colored(f"Error running {command[0]}: {e.stderr}", "yellow"))
        return set()
    except FileNotFoundError:
        if verbose:
            print(colored(f"Error: {command[0]} not found in PATH. Ensure it is installed and accessible.", "yellow"))
        return set()

def read_subdomains_from_file(file_path: str, verbose: bool = False) -> Set[str]:
    if not os.path.exists(file_path):
        if verbose:
            print(colored(f"Error: Subdomain file {file_path} not found.", "yellow"))
        return set()
    
    try:
        with open(file_path, "r") as f:
            subdomains = set(line.strip() for line in f if line.strip())
        if verbose:
            print(colored(f"Read {len(subdomains)} subdomains from {file_path}", "green"))
            if subdomains:
                print(colored(f"Sample subdomains: {list(subdomains)[:5]}", "green"))
        return subdomains
    except Exception as e:
        if verbose:
            print(colored(f"Error reading {file_path}: {str(e)}", "yellow"))
        return set()

def read_urls_from_file(file_path: str, verbose: bool = False) -> Set[str]:
    if not os.path.exists(file_path):
        if verbose:
            print(colored(f"Error: URL file {file_path} not found.", "yellow"))
        return set()
    
    try:
        with open(file_path, "r") as f:
            urls = set(line.strip() for line in f if line.strip() and line.strip().startswith(('http://', 'https://')))
        if verbose:
            print(colored(f"Read {len(urls)} URLs from {file_path}", "green"))
            if urls:
                print(colored(f"Sample URLs: {list(urls)[:5]}", "green"))
        return urls
    except Exception as e:
        if verbose:
            print(colored(f"Error reading {file_path}: {str(e)}", "yellow"))
        return set()

def run_gau(subdomain: str, verbose: bool = False) -> Set[str]:
    return run_command(["gau", "--subs", subdomain, "--threads", "10"], verbose)

def run_waybackurls(subdomain: str, verbose: bool = False) -> Set[str]:
    return run_command(["waybackurls", subdomain], verbose)

def run_hakrawler(subdomain: str, verbose: bool = False) -> Set[str]:
    command = ["bash", "-c", f"echo 'https://{subdomain}' | hakrawler -d 3 -subs -u"]
    return run_command(command, verbose)

def enumerate_urls(subdomains: Set[str] = None, input_file: str = None, output_file: str = "urls.txt", verbose: bool = False) -> Set[str]:
    if not subdomains and not input_file:
        if verbose:
            print(colored("Error: Either subdomains or input_file must be provided.", "yellow"))
        raise ValueError("Either subdomains or input_file must be provided.")

    if input_file and output_file == input_file:
        if verbose:
            print(colored("Error: output_file cannot be the same as input_file.", "yellow"))
        raise ValueError("output_file cannot be the same as input_file.")

    # Read subdomains from file if not provided
    if not subdomains:
        subdomains = read_subdomains_from_file(input_file, verbose)
        if not subdomains:
            return set()

    # Check if output file exists
    if os.path.exists(output_file):
        if verbose:
            print(colored(f"URL file {output_file} exists. Reading from file.", "cyan"))
        return read_urls_from_file(output_file, verbose)

    all_urls = set()

    # Check if tools are installed
    tools = ["gau", "waybackurls", "hakrawler"]
    available_tools = [tool for tool in tools if shutil.which(tool)]
    if not available_tools:
        if verbose:
            print(colored("Error: No URL enumeration tools (gau, waybackurls, hakrawler) found in PATH.", "yellow"))
        return set()
    if verbose:
        print(colored(f"Using tools: {', '.join(available_tools)}", "cyan"))

    # Run URL enumeration tools for each subdomain
    for subdomain in subdomains:
        if verbose:
            print(colored(f"Enumerating URLs for {subdomain}...", "cyan"))

        # Run gau
        if shutil.which("gau"):
            if verbose:
                print(colored(f"Running gau on {subdomain}...", "cyan"))
            all_urls.update(run_gau(subdomain, verbose))

        # Run waybackurls
        if shutil.which("waybackurls"):
            if verbose:
                print(colored(f"Running waybackurls on {subdomain}...", "cyan"))
            all_urls.update(run_waybackurls(subdomain, verbose))

        # Run hakrawler
        if shutil.which("hakrawler"):
            if verbose:
                print(colored(f"Running hakrawler on {subdomain}...", "cyan"))
            all_urls.update(run_hakrawler(subdomain, verbose))

    if verbose:
        print(colored(f"Found {len(all_urls)} unique URLs.", "green"))
        if all_urls:
            print(colored(f"Sample URLs: {list(all_urls)[:5]}", "green"))

    # Save results to output file
    if output_file and all_urls:
        try:
            with open(output_file, "w") as f:
                for url in sorted(all_urls):
                    f.write(f"{url}\n")
            if verbose:
                print(colored(f"Saved {len(all_urls)} URLs to {output_file}", "green"))
        except Exception as e:
            if verbose:
                print(colored(f"Error saving to {output_file}: {str(e)}", "yellow"))

    return all_urls

def main():
    """Parse command-line arguments and enumerate URLs."""
    parser = argparse.ArgumentParser(description="Enumerate URLs for alive subdomains using multiple tools.")
    parser.add_argument("-i", "--input", default="alive_subdomains.txt", help="Input file containing alive subdomains (default: alive_subdomains.txt)")
    parser.add_argument("-o", "--output", default="urls.txt", help="Output file for URLs (default: urls.txt)")
    parser.add_argument("--verbose", action="store_true", help="Print progress and error messages")
    args = parser.parse_args()

    # Validate input and output files
    if args.input == args.output:
        print(colored("Error: Input file cannot be the same as output file.", "yellow"))
        return
    if not os.path.exists(args.input):
        print(colored(f"Error: Input file {args.input} does not exist.", "yellow"))
        return

    # Enumerate or read URLs
    urls = enumerate_urls(input_file=args.input, output_file=args.output, verbose=args.verbose)
    
    if args.verbose:
        print(colored(f"Found {len(urls)} unique URLs.", "green"))
        if urls:
            print(colored(f"Sample URLs: {list(urls)[:5]}", "green"))

if __name__ == "__main__":
    main()
