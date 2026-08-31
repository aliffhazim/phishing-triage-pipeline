#!/usr/bin/env python3
"""
VirusTotal URL Validation Script
Tests a batch of URLs (phishing + safe) against VirusTotal API v3
and logs accuracy/latency results to a CSV file.

SETUP:
1. Paste your VirusTotal API key into API_KEY below (line ~20)
2. Run: python3 validate_urls.py
3. Results will be saved to validation_results.csv

Free tier limits: 4 requests/min, 500/day, 15.5K/month
This script respects the rate limit automatically.
"""

import requests
import base64
import time
import csv
from datetime import datetime

# ============================================
# PASTE YOUR VIRUSTOTAL API KEY HERE
# ============================================
API_KEY = "PASTE_YOUR_API_KEY_HERE"
# ============================================

VT_BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": API_KEY}

# Test URLs: (url, expected_type)
# expected_type: "malicious" or "safe"
TEST_URLS = [
    # Phishing URLs (from OpenPhish feed)
    ("https://facebook-eu.blogspot.com/", "malicious"),
    ("https://https-wvvw-roblox.com/users/338667923/profile", "malicious"),
    ("http://www.netflix-ui-two.vercel.app/", "malicious"),
    ("http://facebook-verify.blogspot.com/?m=1", "malicious"),
    ("https://www.shopeeid-99.blogspot.com/", "malicious"),
    ("https://spotifindnewmusicplaylistdiscoverynow.netlify.app/", "malicious"),
    ("http://apple-ukw.bvyqr.xyz/en/", "malicious"),
    ("https://ssl.uk.ecards.pictures/107519/8af662/475d964a-0243-46bf-aefd-66da26254efa/", "malicious"),
    ("https://fortnite67.lol/", "malicious"),
    ("http://www.linktr.ee/oofrblx/", "malicious"),
    # Safe URLs
    ("https://www.dell.com/", "safe"),
    ("https://www.slb.com/", "safe"),
    ("https://www.siemens-energy.com/", "safe"),
    ("https://www.microsoft.com/", "safe"),
    ("https://www.github.com/", "safe"),
    ("https://www.google.com/", "safe"),
    ("https://www.wazuh.com/", "safe"),
    ("https://www.paloaltonetworks.com/", "safe"),
    ("https://www.n8n.io/", "safe"),
    ("https://www.cisco.com/", "safe"),
]

RATE_LIMIT_DELAY = 16   # seconds between requests (4/min = 1 every 15s, +1s buffer)
POLL_DELAY = 10          # seconds to wait before polling for analysis result
MAX_POLL_ATTEMPTS = 8    # how many times to check if analysis is done


def submit_url(url):
    """Submit a URL to VirusTotal for analysis. Returns analysis ID."""
    resp = requests.post(
        f"{VT_BASE_URL}/urls",
        headers=HEADERS,
        data={"url": url}
    )
    resp.raise_for_status()
    return resp.json()["data"]["id"]


def get_analysis(analysis_id):
    """Poll VirusTotal for the analysis result."""
    resp = requests.get(
        f"{VT_BASE_URL}/analyses/{analysis_id}",
        headers=HEADERS
    )
    resp.raise_for_status()
    return resp.json()


def run_validation():
    results = []
    total = len(TEST_URLS)

    min_estimate = (total * RATE_LIMIT_DELAY) // 60
    max_estimate = (total * (RATE_LIMIT_DELAY + POLL_DELAY * MAX_POLL_ATTEMPTS)) // 60
    print(f"Starting validation of {total} URLs...")
    print(f"Estimated time: ~{min_estimate}-{max_estimate} minutes (depends on how fast VT finishes each scan)\n")

    for i, (url, expected) in enumerate(TEST_URLS, 1):
        print(f"[{i}/{total}] Testing: {url}")
        start_time = time.time()

        try:
            # Step 1: Submit URL
            analysis_id = submit_url(url)

            # Step 2: Poll for result (with retries in case analysis isn't ready)
            status = "queued"
            data = None
            for attempt in range(MAX_POLL_ATTEMPTS):
                time.sleep(POLL_DELAY)
                data = get_analysis(analysis_id)
                status = data["data"]["attributes"]["status"]
                if status == "completed":
                    break
                print(f"    ...analysis {status}, waiting...")

            elapsed = round(time.time() - start_time, 1)

            if status != "completed":
                results.append({
                    "url": url,
                    "expected": expected,
                    "verdict": "TIMEOUT",
                    "malicious_count": "N/A",
                    "correct": "N/A",
                    "time_sec": elapsed
                })
                print(f"    Result: TIMEOUT (analysis not ready)\n")
            else:
                stats = data["data"]["attributes"]["stats"]
                malicious_count = stats["malicious"]
                verdict = "malicious" if malicious_count > 0 else "safe"
                correct = "YES" if verdict == expected else "NO"

                results.append({
                    "url": url,
                    "expected": expected,
                    "verdict": verdict,
                    "malicious_count": malicious_count,
                    "correct": correct,
                    "time_sec": elapsed
                })
                print(f"    Result: {verdict} ({malicious_count} engines flagged) | Expected: {expected} | Correct: {correct}\n")

        except Exception as e:
            results.append({
                "url": url,
                "expected": expected,
                "verdict": "ERROR",
                "malicious_count": "N/A",
                "correct": "N/A",
                "time_sec": "N/A"
            })
            print(f"    ERROR: {e}\n")

        # Rate limit delay before next URL (skip on last one)
        if i < total:
            print(f"    Waiting {RATE_LIMIT_DELAY}s (rate limit)...\n")
            time.sleep(RATE_LIMIT_DELAY)

    return results


def save_results(results):
    filename = "validation_results.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "expected", "verdict", "malicious_count", "correct", "time_sec"])
        writer.writeheader()
        writer.writerows(results)
    print(f"Results saved to {filename}")


def print_summary(results):
    total = len(results)
    correct = sum(1 for r in results if r["correct"] == "YES")
    errors = sum(1 for r in results if r["verdict"] in ("ERROR", "TIMEOUT"))
    valid_results = [r for r in results if isinstance(r["time_sec"], (int, float))]
    avg_time = round(sum(r["time_sec"] for r in valid_results) / len(valid_results), 1) if valid_results else 0

    malicious_set = [r for r in results if r["expected"] == "malicious"]
    safe_set = [r for r in results if r["expected"] == "safe"]

    malicious_correct = sum(1 for r in malicious_set if r["correct"] == "YES")
    malicious_errors = sum(1 for r in malicious_set if r["verdict"] in ("ERROR", "TIMEOUT"))

    safe_correct = sum(1 for r in safe_set if r["correct"] == "YES")
    safe_errors = sum(1 for r in safe_set if r["verdict"] in ("ERROR", "TIMEOUT"))

    print("\n" + "=" * 50)
    print("VALIDATION SUMMARY")
    print("=" * 50)
    print(f"Total tested:     {total}")
    print(f"Correct verdicts: {correct}")
    print(f"Errors/timeouts:  {errors}")
    print(f"Accuracy:         {round((correct / total) * 100, 1)}%")
    print(f"Avg latency:      {avg_time}s per URL")
    print("-" * 50)
    print(f"Malicious set ({len(malicious_set)} URLs): {malicious_correct} correct, {malicious_errors} errors")
    print(f"  -> Detection rate: {round((malicious_correct / len(malicious_set)) * 100, 1)}%" if malicious_set else "")
    print(f"Safe set ({len(safe_set)} URLs):      {safe_correct} correct, {safe_errors} errors")
    print(f"  -> False positive rate: {round(((len(safe_set) - safe_correct - safe_errors) / len(safe_set)) * 100, 1)}%" if safe_set else "")
    print("=" * 50)


if __name__ == "__main__":
    if API_KEY == "PASTE_YOUR_API_KEY_HERE":
        print("ERROR: Please paste your VirusTotal API key into the API_KEY variable at the top of this script.")
        exit(1)

    results = run_validation()
    save_results(results)
    print_summary(results)
