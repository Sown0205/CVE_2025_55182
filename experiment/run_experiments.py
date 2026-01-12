#!/usr/bin/env python3
"""
Automated Experiment Runner for CVE-2025-55182 Research
Runs comprehensive tests for academic paper data collection
"""

import subprocess
import sys
import time
import json
import os
from datetime import datetime

class ExperimentRunner:
    def __init__(self, target_url: str):
        self.target_url = target_url

        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.results_dir = os.path.join(script_dir, "experiment_results")
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create results directory
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)

    def run_command(self, cmd: list, description: str, timeout: int = 300) -> dict:
        """
        Run a command and capture output

        Args:
            cmd: Command to execute as list
            description: Description of what the command does
            timeout: Timeout in seconds (default: 300 = 5 minutes)
        """
        print(f"\n{'='*60}")
        print(f"[*] {description}")
        print(f"{'='*60}")
        print(f"Command: {' '.join(cmd)}\n")
        print(f"[*] Timeout: {timeout} seconds ({timeout//60} minutes)\n")

        start_time = time.time()

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            end_time = time.time()
            duration = end_time - start_time

            print(result.stdout)
            if result.stderr:
                print(f"STDERR:\n{result.stderr}")

            return {
                "success": result.returncode == 0,
                "duration_seconds": duration,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode
            }

        except subprocess.TimeoutExpired:
            print(f"[!] Command timed out after {timeout} seconds ({timeout//60} minutes)")
            return {
                "success": False,
                "duration_seconds": timeout,
                "error": "Timeout",
                "stdout": "",
                "stderr": f"Command exceeded {timeout} second timeout ({timeout//60} minutes)"
            }
        except Exception as e:
            print(f"[!] Error running command: {e}")
            return {
                "success": False,
                "duration_seconds": 0,
                "error": str(e),
                "stdout": "",
                "stderr": str(e)
            }

    def experiment_1_basic_functionality(self):
        """Experiment 1: Verify basic exploit functionality"""
        print("\n" + "#"*60)
        print("# EXPERIMENT 1: Basic Exploit Functionality")
        print("#"*60)

        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        poc_script = os.path.join(script_dir, "poc_enhanced.py")

        cmd = [
            sys.executable,
            poc_script,
            self.target_url,
            "whoami"
        ]

        result = self.run_command(
            cmd,
            "Testing basic exploit with 'whoami' command"
        )

        return {
            "experiment": "basic_functionality",
            "description": "Verify that the exploit successfully executes on vulnerable server",
            "result": result
        }

    def experiment_2_performance_low_rate(self):
        """Experiment 2: Performance test with low request rate"""
        print("\n" + "#"*60)
        print("# EXPERIMENT 2: Performance Analysis (Low Rate)")
        print("#"*60)

        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        poc_script = os.path.join(script_dir, "poc_enhanced.py")

        cmd = [
            sys.executable,
            poc_script,
            self.target_url,
            "whoami",
            "--batch", "50",
            "--delay", "1000"  # 1 second delay
        ]

        result = self.run_command(
            cmd,
            "Sending 50 requests with 1 second delay (1 req/sec)"
        )

        # Rename metrics file (now in script directory)
        metrics_file = os.path.join(script_dir, "exploit_metrics.json")
        if os.path.exists(metrics_file):
            new_name = f"{self.results_dir}/metrics_low_rate_{self.timestamp}.json"
            os.rename(metrics_file, new_name)
            result["metrics_file"] = new_name

        return {
            "experiment": "performance_low_rate",
            "description": "Test server performance under low-rate exploit attempts (1 req/sec)",
            "result": result
        }

    def experiment_3_performance_medium_rate(self):
        """Experiment 3: Performance test with medium request rate"""
        print("\n" + "#"*60)
        print("# EXPERIMENT 3: Performance Analysis (Medium Rate)")
        print("#"*60)

        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        poc_script = os.path.join(script_dir, "poc_enhanced.py")

        cmd = [
            sys.executable,
            poc_script,
            self.target_url,
            "whoami",
            "--batch", "100",
            "--delay", "200"  # 0.2 second delay
        ]

        result = self.run_command(
            cmd,
            "Sending 100 requests with 200ms delay (5 req/sec)"
        )

        # Rename metrics file (now in script directory)
        metrics_file = os.path.join(script_dir, "exploit_metrics.json")
        if os.path.exists(metrics_file):
            new_name = f"{self.results_dir}/metrics_medium_rate_{self.timestamp}.json"
            os.rename(metrics_file, new_name)
            result["metrics_file"] = new_name

        return {
            "experiment": "performance_medium_rate",
            "description": "Test server performance under medium-rate exploit attempts (5 req/sec)",
            "result": result
        }

    def experiment_4_performance_high_rate(self):
        """Experiment 4: Performance test with high request rate (DoS potential)"""
        print("\n" + "#"*60)
        print("# EXPERIMENT 4: Performance Analysis (High Rate - DoS Test)")
        print("#"*60)

        print("\n[!] WARNING: This test may cause server instability or DoS")
        print("[!] Only run in controlled test environment")
        print("[!] Proceeding in 3 seconds...\n")
        time.sleep(3)

        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        poc_script = os.path.join(script_dir, "poc_enhanced.py")

        cmd = [
            sys.executable,
            poc_script,
            self.target_url,
            "whoami",
            "--batch", "200",
            "--delay", "50"  # 50ms delay
        ]

        result = self.run_command(
            cmd,
            "Sending 200 requests with 50ms delay (20 req/sec) - DoS test"
        )

        # Rename metrics file (now in script directory)
        metrics_file = os.path.join(script_dir, "exploit_metrics.json")
        if os.path.exists(metrics_file):
            new_name = f"{self.results_dir}/metrics_high_rate_{self.timestamp}.json"
            os.rename(metrics_file, new_name)
            result["metrics_file"] = new_name

        return {
            "experiment": "performance_high_rate_dos",
            "description": "Test server DoS potential under high-rate exploit attempts (20 req/sec)",
            "result": result
        }

    def experiment_5_performance_aggressive(self):
        """Experiment 5: Aggressive performance test (100 req/sec with 2000 requests)"""
        print("\n" + "#"*60)
        print("# EXPERIMENT 5: Aggressive Performance Analysis (100 req/sec)")
        print("#"*60)

        print("\n[!] WARNING: This test uses aggressive request rates")
        print("[!] Server crash/hang is likely - have restart plan ready")
        print("[!] 100 requests per second for ~20 seconds")
        print("[!] Proceeding in 5 seconds...\n")
        time.sleep(5)

        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        poc_script = os.path.join(script_dir, "poc_enhanced.py")

        cmd = [
            sys.executable,
            poc_script,
            self.target_url,
            "whoami",
            "--batch", "2000",
            "--delay", "10"  # 10ms delay = 100 req/sec
        ]

        result = self.run_command(
            cmd,
            "Sending 2000 requests with 10ms delay (100 req/sec) - Aggressive stress test"
        )

        # Rename metrics file (now in script directory)
        metrics_file = os.path.join(script_dir, "exploit_metrics.json")
        if os.path.exists(metrics_file):
            new_name = f"{self.results_dir}/metrics_aggressive_{self.timestamp}.json"
            os.rename(metrics_file, new_name)
            result["metrics_file"] = new_name

        return {
            "experiment": "performance_aggressive_100rps",
            "description": "Aggressive stress test at 100 req/sec with 2000 total requests (~20s duration)",
            "result": result
        }

    def experiment_6_performance_extreme(self):
        """Experiment 6: Extreme performance test (100 req/sec with 5000 requests)"""
        print("\n" + "#"*60)
        print("# EXPERIMENT 6: Extreme Performance Analysis (100 req/sec Extended)")
        print("#"*60)

        print("\n[!] CRITICAL WARNING: This is an extreme stress test")
        print("[!] Server crash is highly likely")
        print("[!] 100 requests per second for ~50 seconds")
        print("[!] Ensure you can restart the server")
        print("[!] Proceeding in 5 seconds...\n")
        time.sleep(5)

        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        poc_script = os.path.join(script_dir, "poc_enhanced.py")

        cmd = [
            sys.executable,
            poc_script,
            self.target_url,
            "whoami",
            "--batch", "5000",
            "--delay", "10"  # 10ms delay = 100 req/sec
        ]

        # Use extended timeout for extreme test (20 minutes = 1200 seconds)
        # This allows the test to complete even if server becomes very slow
        # Individual requests have 10s timeout, so timeouts are handled gracefully
        result = self.run_command(
            cmd,
            "Sending 5000 requests with 10ms delay (100 req/sec) - Extreme stress test",
            timeout=1200  # 20 minute timeout instead of default 5 minutes
        )

        # Rename metrics file (now in script directory)
        metrics_file = os.path.join(script_dir, "exploit_metrics.json")
        if os.path.exists(metrics_file):
            new_name = f"{self.results_dir}/metrics_extreme_{self.timestamp}.json"
            os.rename(metrics_file, new_name)
            result["metrics_file"] = new_name

        return {
            "experiment": "performance_extreme_100rps_extended",
            "description": "Extreme stress test at 100 req/sec with 5000 total requests (~50s duration)",
            "result": result
        }

    def run_all_experiments(self):
        """Run complete experiment suite"""
        print("\n" + "="*60)
        print(" CVE-2025-55182 (React2Shell) - AUTOMATED EXPERIMENTS")
        print(" For CITA 2026 Research Paper")
        print("="*60)
        print(f"\nTarget: {self.target_url}")
        print(f"Timestamp: {self.timestamp}")
        print(f"Results Directory: {self.results_dir}/")

        all_results = {
            "metadata": {
                "target_url": self.target_url,
                "timestamp": self.timestamp,
                "start_time": datetime.now().isoformat(),
            },
            "experiments": []
        }

        # Run experiments
        experiments = [
            self.experiment_1_basic_functionality,
            self.experiment_2_performance_low_rate,
            self.experiment_3_performance_medium_rate,
            self.experiment_4_performance_high_rate,
            self.experiment_5_performance_aggressive,
            self.experiment_6_performance_extreme,
        ]

        for experiment_func in experiments:
            try:
                result = experiment_func()
                all_results["experiments"].append(result)
            except Exception as e:
                print(f"\n[!] Experiment failed with error: {e}")
                all_results["experiments"].append({
                    "experiment": experiment_func.__name__,
                    "error": str(e),
                    "success": False
                })

            # Small delay between experiments
            time.sleep(3)

        all_results["metadata"]["end_time"] = datetime.now().isoformat()

        # Save comprehensive results
        results_file = f"{self.results_dir}/all_experiments_{self.timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(all_results, f, indent=2)

        print("\n" + "="*60)
        print(" EXPERIMENTS COMPLETED")
        print("="*60)
        print(f"\nAll results saved to: {results_file}")
        print(f"\nIndividual experiment data in: {self.results_dir}/")

        return all_results

    def print_summary(self, results: dict):
        """Print summary of all experiments"""
        print("\n" + "="*60)
        print(" EXPERIMENT SUMMARY")
        print("="*60)

        total = len(results["experiments"])
        successful = sum(1 for exp in results["experiments"]
                        if exp.get("result", {}).get("success", False))

        print(f"\nTotal Experiments: {total}")
        print(f"Successful: {successful}")
        print(f"Failed: {total - successful}")

        print("\n[*] Experiment List:")
        for exp in results["experiments"]:
            name = exp.get("experiment", "unknown")
            desc = exp.get("description", "")
            success = exp.get("result", {}).get("success", False)
            status = "✓" if success else "✗"

            print(f"  {status} {name}")
            print(f"     {desc}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python run_experiments.py <target_url>")
        print("\nExample:")
        print("  python run_experiments.py http://localhost:3000")
        print("\nThis will run all experiments for the research paper:")
        print("  1. Basic functionality test")
        print("  2. Performance analysis (low rate - 1 req/sec)")
        print("  3. Performance analysis (medium rate - 5 req/sec)")
        print("  4. Performance analysis (high rate - 20 req/sec)")
        print("  5. Aggressive stress test (100 req/sec, 2000 requests)")
        print("  6. Extreme stress test (100 req/sec, 5000 requests)")
        print("\nWARNING: Experiments 5-6 may crash the server!")
        print("WARNING: Only run against test servers in controlled environments!")
        sys.exit(1)

    target_url = sys.argv[1]

    print("\n[!] IMPORTANT: This will run multiple exploit attempts")
    print("[!] against the target server for research purposes.")
    print("[!] Ensure you have authorization and are testing in a")
    print("[!] controlled, isolated environment.")
    print("\nContinue? (yes/no): ", end="")

    response = input().strip().lower()
    if response != "yes":
        print("\n[*] Experiments cancelled.")
        sys.exit(0)

    runner = ExperimentRunner(target_url)
    results = runner.run_all_experiments()
    runner.print_summary(results)


if __name__ == "__main__":
    main()
