import subprocess
import os
import shutil
import uuid
from typing import Set, Dict
import json
import re

def run_command(command: list, verbose: bool = False) -> str:
    try:
        env = os.environ.copy()
        env["PATH"] = f"/usr/bin:/usr/local/bin:{os.path.expanduser('~/bin')}:{env.get('PATH', '')}"
        result = subprocess.run(command, capture_output=True, text=True, check=True, env=env)
        return result.stdout
    except subprocess.CalledProcessError as e:
        if verbose:
            print(f"Error running {command[0]}: {e.stderr}")
        return ""
    except FileNotFoundError:
        if verbose:
            print(f"Error: {command[0]} not found in PATH. Ensure it is installed and accessible.")
        return ""

def read_subdomains_from_file(file_path: str, verbose: bool = False) -> Set[str]:
    if not os.path.exists(file_path):
        if verbose:
            print(f"Error: Subdomain file {file_path} not found.")
        return set()
    
    with open(file_path, "r") as f:
        subdomains = set(line.strip() for line in f if line.strip())
    if verbose:
        print(f"Read {len(subdomains)} subdomains from {file_path}")
    return subdomains

def read_alive_subdomains_from_file(file_path: str, valid_subdomains: Set[str], verbose: bool = False) -> Dict[str, int]:
    if not os.path.exists(file_path):
        if verbose:
            print(f"Error: Alive subdomain file {file_path} not found.")
        return {}
    
    with open(file_path, "r") as f:
        subdomains = set(line.strip() for line in f if line.strip())
    if verbose:
        print(f"Read {len(subdomains)} subdomains from {file_path}")
    
    # Validate subdomains against valid_subdomains
    subdomain_pattern = re.compile(r'^(' + '|'.join(re.escape(sub) for sub in valid_subdomains) + r')$')
    alive_subdomains = {sub: 200 for sub in subdomains if subdomain_pattern.match(sub)}
    
    if verbose:
        print(f"Found {len(alive_subdomains)} valid alive subdomains after cleaning.")
    return alive_subdomains

def run_httpx(subdomains: Set[str] = None, input_file: str = None, output_file: str = "alive_subdomains.txt", verbose: bool = False) -> Dict[str, int]:
    if not shutil.which("httpx"):
        if verbose:
            print("Error: httpx not found in PATH. Please install it.")
        return {}

    # Ensure at least one input source is provided
    if not subdomains and not input_file:
        if verbose:
            print("Error: Either subdomains or input_file must be provided.")
        raise ValueError("Either subdomains or input_file must be provided.")

    # Prevent output_file from matching input_file
    if input_file and output_file == input_file:
        if verbose:
            print("Error: output_file cannot be the same as input_file.")
        raise ValueError("output_file cannot be the same as input_file.")

    # Read subdomains from file if not provided
    if not subdomains:
        subdomains = read_subdomains_from_file(input_file, verbose)
        if not subdomains:
            return {}

    # Check if output file exists
    if os.path.exists(output_file):
        if verbose:
            print(f"Alive subdomain file {output_file} exists. Skipping httpx and reading from file.")
        return read_alive_subdomains_from_file(output_file, subdomains, verbose)

    temp_input_file = input_file
    if not input_file and subdomains:
        temp_input_file = f"temp_subdomains_{uuid.uuid4().hex}.txt"
        if verbose:
            print(f"Creating temporary input file: {temp_input_file}")
        with open(temp_input_file, "w") as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")

    if not temp_input_file or not os.path.exists(temp_input_file):
        if verbose:
            print(f"Error: Input file {temp_input_file} does not exist.")
        if temp_input_file != input_file and os.path.exists(temp_input_file):
            os.remove(temp_input_file)
        return {}

    try:
        if verbose:
            print(f"Running httpx on input file: {temp_input_file}")
        command = ["httpx", "-l", temp_input_file, "-silent", "-sc", "-json"]
        result = run_command(command, verbose)
        alive_subdomains = {}
        
        # Parse JSON output from httpx
        for line in result.splitlines():
            try:
                data = json.loads(line.strip())
                subdomain = data.get("url", "").replace("http://", "").replace("https://", "")
                status_code = data.get("status_code")
                if status_code == 200 and subdomain in subdomains:
                    alive_subdomains[subdomain] = status_code
                    if verbose:
                        print(f"Alive subdomain: {subdomain} (Status: {status_code})")
            except json.JSONDecodeError:
                if verbose:
                    print(f"Skipping invalid JSON line: {line}")
                continue

        # Save results to output file
        if output_file and alive_subdomains:
            if verbose:
                print(f"Saving alive subdomains to: {output_file}")
            with open(output_file, "w") as f:
                for subdomain in sorted(alive_subdomains.keys()):
                    f.write(f"{subdomain}\n")
            if verbose:
                print(f"Alive subdomains saved to {output_file}")

        return alive_subdomains

    except Exception as e:
        if verbose:
            print(f"Error running httpx: {str(e)}")
        return {}
    finally:
        # Clean up temporary file
        if temp_input_file != input_file and os.path.exists(temp_input_file):
            if verbose:
                print(f"Cleaning up temporary file: {temp_input_file}")
            os.remove(temp_input_file)

def main():
    """Parse command-line arguments and check alive subdomains."""
    parser = argparse.ArgumentParser(description="Check alive subdomains with httpx.")
    parser.add_argument("-i", "--input", default="subdomains.txt", help="Input file containing subdomains (default: subdomains.txt)")
    parser.add_argument("-o", "--output", default="alive_subdomains.txt", help="Output file for alive subdomains (default: alive_subdomains.txt)")
    parser.add_argument("--verbose", action="store_true", help="Print progress and error messages")
    args = parser.parse_args()

    # Validate input and output files
    if args.input == args.output:
        print("Error: Input file cannot be the same as output file.")
        return
    if not os.path.exists(args.input):
        print(f"Error: Input file {args.input} does not exist.")
        return

    # Check alive subdomains
    alive_subdomains = run_httpx(set(), input_file=args.input, output_file=args.output, verbose=args.verbose)
    
    if args.verbose:
        print(f"Found {len(alive_subdomains)} alive subdomains with status code 200.")

if __name__ == "__main__":
    main()
