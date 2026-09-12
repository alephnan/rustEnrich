#!/usr/bin/env python3
"""Opt-in file-based smoke client; Bash entry point: test_indicators.sh."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = {"abuseipdb", "virustotal"}
STATUSES = {"ok", "not_found", "unsupported", "disabled", "rate_limited", "timeout", "error"}
MAX_INPUT_BYTES = 1_048_576


def read_input(path):
    if not path.is_file():
        raise ValueError("Indicator file must be a readable regular file.")
    with path.open("rb") as source:
        raw = source.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("Indicator file exceeds 1 MiB.")
    content = raw.decode("utf-8-sig")
    entries = []
    for number, line in enumerate(content.split("\n"), 1):
        line = line.removesuffix("\r")
        if not line.strip(" \t") or line.lstrip(" \t").startswith("#"):
            continue
        match = re.fullmatch(r"(ip|url|hash)[ \t]+(\S+)", line)
        if not match:
            raise ValueError(f"Line {number}: expected type followed by one whitespace-free value.")
        kind, value = match.groups()
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError(f"Line {number}: control characters are not allowed.")
        if len(value.encode("utf-8")) > 4096:
            raise ValueError(f"Line {number}: value exceeds 4,096 bytes.")
        if kind == "hash" and not re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", value):
            raise ValueError(f"Line {number}: expected an MD5, SHA-1 or SHA-256 hash.")
        entries.append((number, {"type": kind, "value": value}))
        if len(entries) > 1000:
            raise ValueError("Indicator file exceeds 1,000 entries.")
    if not entries:
        raise ValueError("Indicator file contains no entries.")
    return entries


def read_token(path):
    if not path.is_file():
        raise ValueError("Service token file must be a readable regular file.")
    token = path.read_bytes().decode("ascii")
    token = token.removesuffix("\r\n") if token.endswith("\r\n") else token.removesuffix("\n")
    if not re.fullmatch(r"[!-~]{32,}", token):
        raise ValueError("Expected a service token of at least 32 visible ASCII characters.")
    return token


def arguments():
    parser = argparse.ArgumentParser(
        description="Submit a file of 'type value' lines to rustEnrich, one request at a time.",
        epilog="No client retries. Exit codes: 0 completed/dry run, 1 request/provider failure, 2 setup/input error.",
    )
    parser.add_argument("file", type=Path, help="UTF-8 text: ip, url or hash plus a value; blank/# lines ignored")
    parser.add_argument("--providers", help="comma-separated abuseipdb,virustotal; defaults to enabled providers")
    parser.add_argument("--token-file", type=Path, default=ROOT / "secrets/service_token")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080", help="service origin")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data/test-results", help="parent directory for a new run")
    parser.add_argument("--delay", type=int, default=31, help="seconds between requests, 0..3600 (default: 31)")
    parser.add_argument("--raw", action="store_true", help="include available raw reports in saved responses")
    parser.add_argument("--dry-run", action="store_true", help="check file format only; no token or network needed")
    args = parser.parse_args()
    if not 0 <= args.delay <= 3600:
        parser.error("delay must be from 0 to 3600 seconds")
    if args.providers is not None:
        args.providers = args.providers.split(",")
        if len(set(args.providers)) != len(args.providers) or not set(args.providers) <= PROVIDERS:
            parser.error("use distinct abuseipdb and/or virustotal provider IDs")
    try:
        url = urlsplit(args.base_url)
        valid = (url.scheme in {"http", "https"} and url.hostname and
                 url.username is None and url.password is None and
                 url.path in {"", "/"} and not url.query and not url.fragment and
                 not re.search(r"[\s\\?#]", args.base_url))
        if not valid or url.port == 0:
            raise ValueError
    except ValueError:
        parser.error("base URL must be an HTTP(S) origin without credentials, path, query or fragment")
    args.base_url = args.base_url.rstrip("/")
    return args


def provider_results(path):
    """Check the fields used for reporting before trusting a service response."""
    envelope = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(envelope, dict) or not isinstance(envelope.get("request_id"), str):
        raise ValueError
    results = envelope.get("results")
    if not isinstance(results, list) or len(results) != 1 or results[0]["index"] != 0:
        raise ValueError
    providers = results[0]["providers"]
    if not isinstance(providers, list) or not providers:
        raise ValueError
    for result in providers:
        if (result["provider"] not in PROVIDERS or result["status"] not in STATUSES or
                type(result["cache"]["hit"]) is not bool):
            raise ValueError
        error = result.get("error")
        if error is not None and not isinstance(error, dict):
            raise ValueError
    return providers


def run(args, entries, token, curl):
    args.output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=args.output_dir)).resolve()
    print(f"Responses: {run_dir}", flush=True)
    print("Each uncached supported pair can consume 1 attempt, or 2 with a service retry. Cache hits consume none.")
    print("Actual upstream usage is not exposed by this API; check provider dashboards for exact usage.")
    with tempfile.TemporaryDirectory(prefix="rustenrich-client-") as temporary, (run_dir / "index.tsv").open("w", encoding="utf-8") as index:
        header_file = Path(temporary) / "auth-header"
        request_file = Path(temporary) / "request.json"
        header_file.write_text(f"Authorization: Bearer {token}\n", encoding="ascii")
        index.write("request\tsource_line\ttype\thttp_status\tresponse_file\n")
        for number, (source_line, indicator) in enumerate(entries, 1):
            if number > 1:
                time.sleep(args.delay)
            response = run_dir / f"{number:04d}.json"
            payload = {"indicators": [indicator], "include_raw": args.raw}
            if args.providers is not None:
                payload["providers"] = args.providers
            request_file.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            print(f"[{number}/{len(entries)}] Line {source_line} ({indicator['type']})", flush=True)
            # Private files keep both credentials and indicator values out of argv.
            # Disable curlrc, proxies, redirects and client retries; bound total time.
            command = [curl, "--disable", "--silent", "--show-error", "--noproxy", "*",
                       "--proto", "=http,https", "--connect-timeout", "5", "--max-time", "25",
                       "--request", "POST", "--header", f"@{header_file}",
                       "--header", "Content-Type: application/json", "--data-binary", f"@{request_file}",
                       "--output", str(response), "--write-out", "%{http_code}", f"{args.base_url}/v1/enrich"]
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
                http_status = completed.stdout if completed.returncode == 0 else "transport_error"
            except subprocess.TimeoutExpired:
                http_status = "transport_error"
            index.write(f"{number}\t{source_line}\t{indicator['type']}\t{http_status}\t{response.name}\n")
            index.flush()
            if http_status != "200":
                print(f"Request failed ({http_status}). Inspect {response}; remaining indicators were not sent.", file=sys.stderr)
                return 1
            try:
                providers = provider_results(response)
            except (OSError, ValueError, KeyError, TypeError):
                print(f"Unexpected response format. Inspect {response}; remaining indicators were not sent.", file=sys.stderr)
                return 1
            for result in providers:
                message = f"  {result['provider']}: {result['status']} cache.hit={str(result['cache']['hit']).lower()}"
                if result.get("error") is not None:
                    error = result["error"]
                    message += f" error={json.dumps(error.get('code'))} retry_after_seconds={json.dumps(error.get('retry_after_seconds'))}"
                print(message, flush=True)
            if any(result["status"] not in {"ok", "not_found", "unsupported"} for result in providers):
                print("Stopped on a provider failure or disabled selection. Successful results were retained; remaining indicators were not sent.", file=sys.stderr)
                return 1
    print(f"Completed {len(entries)} service requests. Results and source-line index: {run_dir}")
    return 0


def main():
    os.umask(0o077)
    args = arguments()
    try:
        entries = read_input(args.file)
        selected = ",".join(args.providers) if args.providers else "enabled providers"
        print(f"Loaded {len(entries)} indicators. Providers: {selected}. Delay: {args.delay}s.")
        print("IP and URL validity is checked by the service when each entry is submitted.")
        if args.dry_run:
            print("Dry run complete: no credentials read and no requests sent.")
            return 0
        curl = shutil.which("curl")
        if curl is None:
            raise ValueError("curl is required. On Arch: sudo pacman -S curl")
        token = read_token(args.token_file)
        return run(args, entries, token, curl)
    except UnicodeError:
        print("Error: indicator files must be UTF-8; service tokens must be ASCII.", file=sys.stderr)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
    except OSError:
        print("Error: could not read input/token files, write results, or execute curl. Check paths and permissions.", file=sys.stderr)
    except KeyboardInterrupt:
        print("Interrupted. Completed response files were retained.", file=sys.stderr)
        return 130
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
