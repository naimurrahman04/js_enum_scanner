#!/usr/bin/env python3
import re
import sys
import requests
import time
import json
import argparse
import concurrent.futures
from urllib.parse import urljoin, urlparse
from datetime import datetime
from collections import defaultdict

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/137.0.0.0 Safari/537.36"
    )
}

DEFAULT_TOKEN_PATTERNS = ["api_key", "apikey", "token", "auth", "secret", "access_token"]
COMMON_PARAM_NAMES = ["id", "user", "name", "token", "auth", "search", "q", "lang", "ref", "type", "debug"]
IGNORED_EXTENSIONS = ("jquery", "bootstrap", "analytics", "google")

ENDPOINT_REGEX = re.compile(r'(["\'])(/[^"\']+?|https?://[^"\']+?|\.{1,2}/[^"\']+?|\w+\.(php|json|jsp|cgi|action|aspx))\1')
FETCH_REGEX = re.compile(r'fetch\(("|\'|`)(.+?)(\1)')
AXIOS_REGEX = re.compile(r'axios\.(get|post|put|delete)\(("|\'|`)(.+?)(\2)')
XHR_REGEX = re.compile(r'open\(("|\'|`)(GET|POST|PUT|DELETE)(\1),\s*("|\'|`)(.+?)(\4)')
GRAPHQL_REGEX = re.compile(r'graphql|ApolloClient', re.IGNORECASE)
PARAM_REGEX = re.compile(r'[\?&]([a-zA-Z0-9_\-]+)=?')


def extract_links(js_text, base_url):
    found = set()
    for regex in [ENDPOINT_REGEX, FETCH_REGEX, AXIOS_REGEX, XHR_REGEX]:
        for match in regex.finditer(js_text):
            url = match.group(2)
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = urljoin(base_url, url)
            elif url.startswith("http"):
                pass
            elif url.startswith("."):
                url = urljoin(base_url + "/", url)
            else:
                url = urljoin(base_url, "/" + url)
            found.add(url)
    return found


def extract_parameters(text):
    return set(PARAM_REGEX.findall(text))


def extract_tokens(text, token_patterns):
    token_regex = re.compile(r'(' + '|'.join(token_patterns) + r')["\'\s:=]+([a-zA-Z0-9_\-\.]+)', re.IGNORECASE)
    return set(f"{k}={v}" for k, v in token_regex.findall(text))


def get_js_links(html_text):
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_text)


def extract_inline_js(html_text):
    return re.findall(r'<script[^>]*>(.*?)</script>', html_text, re.DOTALL)


def should_ignore_js(file):
    return any(ignored in file for ignored in IGNORED_EXTENSIONS)


def fetch_js_and_extract(js_url, base_url, token_patterns):
    try:
        resp = requests.get(js_url, headers=HEADERS, timeout=10)
        if resp.status_code != 200:
            return set(), set(), set(), False
        text = resp.text
        endpoints = extract_links(text, base_url)
        params = extract_parameters(text)
        tokens = extract_tokens(text, token_patterns)
        is_graphql = bool(GRAPHQL_REGEX.search(text))
        return endpoints, params, tokens, is_graphql
    except requests.RequestException:
        return set(), set(), set(), False


def fuzz_parameters(endpoint, common_params):
    discovered = set()
    for param in common_params:
        try:
            sep = "&" if "?" in endpoint else "?"
            url = f"{endpoint}{sep}{param}=test"
            resp = requests.get(url, headers=HEADERS, timeout=5)
            if resp.status_code in [200, 403, 500]:
                discovered.add(param)
        except requests.RequestException:
            continue
    return discovered


def scan_target(url, custom_tokens, custom_params, max_threads):
    token_patterns = DEFAULT_TOKEN_PATTERNS + [t.strip() for t in custom_tokens if t.strip()]
    param_list = COMMON_PARAM_NAMES + [p.strip() for p in custom_params if p.strip()]

    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    endpoints, params, tokens = set(), set(), set()
    graphql_found = False

    try:
        print("[INFO] Fetching main page...")
        resp = requests.get(url, headers=HEADERS, timeout=10)
        html = resp.text
    except Exception as e:
        print(f"[ERROR] Could not fetch target: {e}")
        return

    js_links = get_js_links(html)
    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_threads) as executor:
        for js in js_links:
            if should_ignore_js(js):
                continue
            full_url = urljoin(base, js)
            tasks.append(executor.submit(fetch_js_and_extract, full_url, base, token_patterns))

        for task in concurrent.futures.as_completed(tasks):
            e, p, t, gq = task.result()
            endpoints.update(e)
            params.update(p)
            tokens.update(t)
            graphql_found = graphql_found or gq

    for block in extract_inline_js(html):
        endpoints.update(extract_links(block, base))
        params.update(extract_parameters(block))
        tokens.update(extract_tokens(block, token_patterns))
        if GRAPHQL_REGEX.search(block):
            graphql_found = True

    for ep in endpoints:
        params.update(fuzz_parameters(ep, param_list))

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = f"scan_report_{timestamp}.json"
    result = {
        "url": url,
        "endpoints": sorted(endpoints),
        "parameters": sorted(params),
        "tokens": sorted(tokens),
        "graphql_used": graphql_found
    }
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[INFO] Scan complete. Results saved to {result_file}")
    return result_file


def main():
    parser = argparse.ArgumentParser(description="JavaScript Endpoint & Parameter Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--tokens", help="Custom token keywords (comma-separated)", default="")
    parser.add_argument("--params", help="Custom parameter names (comma-separated)", default="")
    parser.add_argument("--threads", type=int, help="Maximum threads for JS fetching", default=5)
    args = parser.parse_args()

    custom_tokens = args.tokens.split(",") if args.tokens else []
    custom_params = args.params.split(",") if args.params else []

    scan_target(args.url, custom_tokens, custom_params, args.threads)


if __name__ == "__main__":
    main()
