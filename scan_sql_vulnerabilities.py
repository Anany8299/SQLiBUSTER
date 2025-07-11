import os
import subprocess
import json
import re
from typing import Set, Dict
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
import uuid
import shutil

STATIC_EXTS = ('.js', '.png', '.jpg', '.jpeg', '.gif', '.css', '.woff', '.woff2', '.ttf', '.svg')
RAM_LOG_DIR = "/dev/shm/sqlmap_logs"

def read_urls_from_file(file_path: str = "urls.txt", verbose: bool = False) -> Set[str]:
    if not os.path.exists(file_path):
        if verbose:
            print(colored(f"Error: URL file {file_path} not found.", "yellow"))
        return set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            urls = set(line.strip() for line in f if line.strip().startswith(("http://", "https://")))
        if verbose:
            print(colored(f"Read {len(urls)} URLs from {file_path}", "green"))
        return urls
    except Exception as e:
        if verbose:
            print(colored(f"Error reading {file_path}: {str(e)}", "yellow"))
        return set()

def filter_urls_with_gf(urls: Set[str], input_file: str = "urls.txt", verbose: bool = False) -> Set[str]:
    gf_binary = shutil.which("gf") or "/usr/bin/gf"
    gf_path = "/home/kali/.gf"  # Change if needed
    sqli_json = os.path.join(gf_path, "sqli.json")

    if not os.path.exists(input_file):
        if verbose:
            print(colored(f"Error: Input file {input_file} not found.", "yellow"))
        return urls

    if not os.path.exists(sqli_json):
        if verbose:
            print(colored(f"Error: {sqli_json} not found.", "yellow"))
        return urls

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            clean_urls = [line.strip() for line in f if line.strip()]
            input_data = "\n".join(clean_urls)

        if verbose:
            print(colored(f"Feeding {len(clean_urls)} URLs into gf", "cyan"))

        gf_env = os.environ.copy()
        gf_env["GF_PATH"] = gf_path

        process = subprocess.Popen(
            [gf_binary, "sqli"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=gf_env,
            text=True
        )

        stdout, stderr = process.communicate(input=input_data)

        if stderr.strip() and verbose:
            print(colored(f"gf stderr: {stderr.strip()}", "yellow"))

        filtered_urls = set(
            line.strip() for line in stdout.splitlines()
            if line.strip().startswith(('http://', 'https://')) and '?' in line
        )

        if verbose:
            print(colored(f"Filtered {len(filtered_urls)} URLs with gf", "green"))

        return filtered_urls if filtered_urls else urls

    except Exception as e:
        if verbose:
            print(colored(f"Exception in gf filtering: {e}", "yellow"))
        return urls

def run_sqlmap(url: str, verbose: bool = False) -> Dict[str, any]:
    if any(url.lower().endswith(ext) for ext in STATIC_EXTS):
        if verbose:
            print(colored(f"[sqlmap] Skipping (static asset): {url}", "yellow"))
        return {"url": url, "vulnerable": False, "details": {}}

    if verbose:
        print(colored(f"[sqlmap] Scanning: {url}", "cyan"))

    try:
        scan_id = uuid.uuid4().hex[:8]
        out_dir = os.path.join(RAM_LOG_DIR, scan_id)
        os.makedirs(out_dir, exist_ok=True)

        command = [
            "sqlmap", "-u", url,
            "--level", "5", "--risk", "3",
            "--threads", "10",
            "--timeout", "5", "--retries", "0",
            "--ignore-timeouts",
            "--batch",
            "--skip-waf",
            "--random-agent",
            "--technique", "BEUSTQ",
            "--dbs",
            f"--output-dir={out_dir}",
            "-v", "2"
        ]

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        full_output = []
        for line in process.stdout:
            line = line.strip()
            full_output.append(line)

            if "[INFO]" in line:
                color = "green"
            elif "[WARNING]" in line:
                color = "yellow"
            elif "[CRITICAL]" in line or "[ERROR]" in line:
                color = "red"
            elif "[PAYLOAD]" in line:
                color = "magenta"
            else:
                color = "white"

            print(colored(f"[sqlmap] {line}", color))

        output_text = "\n".join(full_output)
        result_dict = {"url": url, "vulnerable": False, "details": {}}

        if "sqlmap identified the following injection point" in output_text.lower():
            result_dict["vulnerable"] = True

            param_match = re.search(r"Parameter: (\S+)", output_text)
            dbms_match = re.search(r"back-end DBMS: (\S+)", output_text)
            dbs_match = re.search(r"available databases \[\d+\]:\n((?:\[.*?\]\n)+)", output_text)

            if param_match:
                result_dict["details"]["parameter"] = param_match.group(1)
            if dbms_match:
                result_dict["details"]["dbms"] = dbms_match.group(1)
            if dbs_match:
                result_dict["details"]["databases"] = [db.strip("[]") for db in dbs_match.group(1).splitlines()]

        return result_dict

    except Exception as e:
        if verbose:
            print(colored(f"[sqlmap] Error running sqlmap on {url}: {e}", "red"))
        return {"url": url, "vulnerable": False, "details": {}}

def scan_sql_vulnerabilities(input_file: str = "urls.txt", output_file: str = "sql_vulnerabilities.txt", verbose: bool = False) -> Dict[str, any]:
    if verbose:
        print(colored("WARNING: Only scan authorized targets!", "red"))

    urls = read_urls_from_file(input_file, verbose)
    if not urls:
        if verbose:
            print(colored("No valid URLs found.", "yellow"))
        return {}

    filtered_urls = filter_urls_with_gf(urls, input_file, verbose)

    #filter before scan
    filtered_urls = {u for u in filtered_urls if '?' in u and not any(k in u for k in ['utm_', 'gclid', 'fbclid'])}

    results = {}

    # Parallel scanning
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(run_sqlmap, url, verbose): url for url in filtered_urls}

        for future in as_completed(futures):
            url = futures[future]
            try:
                results[url] = future.result()
            except Exception as e:
                if verbose:
                    print(colored(f"[!] Exception while scanning {url}: {e}", "red"))

    if output_file:
        try:
            with open(output_file, "w") as f:
                json.dump(results, f, indent=2)
            if verbose:
                print(colored(f"Results saved to {output_file}", "green"))
        except Exception as e:
            if verbose:
                print(colored(f"Error saving results: {e}", "yellow"))

    return results

# Optional CLI runner
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SQLiBUSTER: Fast SQL Injection Scanner")
    parser.add_argument("-i", "--input", default="urls.txt", help="Input file containing URLs")
    parser.add_argument("-o", "--output", default="sql_vulnerabilities.txt", help="Output file for results")
    parser.add_argument("--verbose", action="store_true", help="Verbose mode")
    args = parser.parse_args()

    scan_sql_vulnerabilities(args.input, args.output, args.verbose)
