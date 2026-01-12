#!/usr/bin/env python3
"""
Results Analysis and Visualization Tool
Processes experiment data and generates paper-ready statistics and graphs
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List
import statistics

try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Use non-GUI backend
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("[!] matplotlib not installed. Install with: pip install matplotlib")
    print("[*] Will generate text-based analysis only.\n")


class ResultsAnalyzer:
    def __init__(self, results_dir: str = "experiment_results"):
        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # If results_dir is just a name (not an absolute path), make it relative to script directory
        if not os.path.isabs(results_dir):
            self.results_dir = os.path.join(script_dir, results_dir)
        else:
            self.results_dir = results_dir

        self.data = {}

    def load_all_data(self):
        """Load all JSON result files"""
        print(f"[*] Loading data from {self.results_dir}/")

        if not os.path.exists(self.results_dir):
            print(f"[-] Directory not found: {self.results_dir}")
            print("[!] Run experiments first: python run_experiments.py http://localhost:3000")
            return False

        json_files = list(Path(self.results_dir).glob("*.json"))

        if not json_files:
            print(f"[-] No JSON files found in {self.results_dir}")
            return False

        for json_file in json_files:
            print(f"[+] Loading {json_file.name}")
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)

                # Categorize data by type
                if "low_rate" in json_file.name:
                    self.data['low_rate'] = data
                elif "medium_rate" in json_file.name:
                    self.data['medium_rate'] = data
                elif "aggressive" in json_file.name:
                    self.data['aggressive'] = data
                elif "extreme" in json_file.name:
                    self.data['extreme'] = data
                elif "high_rate" in json_file.name:
                    self.data['high_rate'] = data
                elif "waf_bypass" in json_file.name:
                    self.data['waf_bypass'] = data
                elif "all_experiments" in json_file.name:
                    self.data['all_experiments'] = data

            except Exception as e:
                print(f"[!] Error loading {json_file}: {e}")

        print(f"\n[+] Loaded {len(self.data)} datasets\n")
        return True

    def _calculate_stats_from_metrics(self, metrics: List[Dict]) -> Dict:
        """Calculate statistics from metrics array"""
        if not metrics:
            return {}

        response_times = [m['response_time_ms'] for m in metrics if m.get('success', False)]

        if not response_times:
            return {}

        success_count = sum(1 for m in metrics if m.get('success', False))
        total_count = len(metrics)

        return {
            'mean_ms': statistics.mean(response_times),
            'median_ms': statistics.median(response_times),
            'stdev_ms': statistics.stdev(response_times) if len(response_times) > 1 else 0,
            'min_ms': min(response_times),
            'max_ms': max(response_times),
            'p95_ms': statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else max(response_times),
            'p99_ms': statistics.quantiles(response_times, n=100)[98] if len(response_times) >= 100 else max(response_times),
            'success_rate': (success_count / total_count * 100) if total_count > 0 else 0,
            'success_count': success_count,
            'total_count': total_count
        }

    def generate_paper_statistics(self):
        """Generate key statistics for paper"""
        print("="*60)
        print(" KEY STATISTICS FOR PAPER")
        print("="*60)

        stats = {}

        # Performance metrics
        if 'low_rate' in self.data:
            analysis = self.data['low_rate'].get('analysis', {})
            rt = analysis.get('response_times', {})

            stats['baseline_mean_response'] = rt.get('mean_ms', 0)
            stats['baseline_stdev'] = rt.get('stdev_ms', 0)
            stats['baseline_success_rate'] = analysis.get('success_rate', 0)
            stats['payload_size'] = analysis.get('payload_size_bytes', 0)

            print("\n[*] Baseline Performance (Low Rate - 1 req/sec):")
            print(f"    Mean Response Time: {stats['baseline_mean_response']:.2f} ms")
            print(f"    Std Deviation: {stats['baseline_stdev']:.2f} ms")
            print(f"    Success Rate: {stats['baseline_success_rate']:.2f}%")
            print(f"    Payload Size: {stats['payload_size']} bytes")

        # Compare rates
        if 'medium_rate' in self.data and 'high_rate' in self.data:
            medium_rt = self.data['medium_rate'].get('analysis', {}).get('response_times', {}).get('mean_ms', 0)
            high_rt = self.data['high_rate'].get('analysis', {}).get('response_times', {}).get('mean_ms', 0)

            if 'baseline_mean_response' in stats and stats['baseline_mean_response'] > 0:
                medium_increase = ((medium_rt - stats['baseline_mean_response']) / stats['baseline_mean_response']) * 100
                high_increase = ((high_rt - stats['baseline_mean_response']) / stats['baseline_mean_response']) * 100

                stats['medium_rate_increase'] = medium_increase
                stats['high_rate_increase'] = high_increase

                print(f"\n[*] Performance Degradation:")
                print(f"    Medium Rate (5 req/sec): {medium_increase:+.1f}% vs baseline")
                print(f"    High Rate (20 req/sec): {high_increase:+.1f}% vs baseline")

            medium_success = self.data['medium_rate'].get('analysis', {}).get('success_rate', 0)
            high_success = self.data['high_rate'].get('analysis', {}).get('success_rate', 0)

            print(f"\n[*] Success Rates by Request Rate:")
            print(f"    Low Rate (1 req/sec): {stats.get('baseline_success_rate', 0):.1f}%")
            print(f"    Medium Rate (5 req/sec): {medium_success:.1f}%")
            print(f"    High Rate (20 req/sec): {high_success:.1f}%")

            # DoS assessment
            if high_success < 80:
                print(f"\n[!] DoS Potential: Server availability significantly degraded at 20 req/sec")
                print(f"    (Success rate dropped to {high_success:.1f}%)")

        # Aggressive stress test analysis (100 req/sec, 2000 requests)
        if 'aggressive' in self.data:
            print(f"\n[*] Aggressive Stress Test (100 req/sec, 2000 requests):")
            aggressive_metrics = self.data['aggressive'].get('metrics', [])

            if aggressive_metrics:
                agg_stats = self._calculate_stats_from_metrics(aggressive_metrics)

                print(f"    Total Requests: {agg_stats.get('total_count', 0)}")
                print(f"    Success Rate: {agg_stats.get('success_rate', 0):.1f}%")
                print(f"    Mean Response Time: {agg_stats.get('mean_ms', 0):.2f} ms")
                print(f"    Median Response Time: {agg_stats.get('median_ms', 0):.2f} ms")
                print(f"    Std Deviation: {agg_stats.get('stdev_ms', 0):.2f} ms")
                print(f"    Min: {agg_stats.get('min_ms', 0):.2f} ms")
                print(f"    Max: {agg_stats.get('max_ms', 0):.2f} ms")
                print(f"    P95: {agg_stats.get('p95_ms', 0):.2f} ms")
                print(f"    P99: {agg_stats.get('p99_ms', 0):.2f} ms")

                # Calculate degradation vs baseline
                if 'baseline_mean_response' in stats and stats['baseline_mean_response'] > 0:
                    agg_increase = ((agg_stats['mean_ms'] - stats['baseline_mean_response']) / stats['baseline_mean_response']) * 100
                    print(f"    Performance Degradation: {agg_increase:+.1f}% vs baseline")

                    # Variance ratio
                    if 'baseline_stdev' in stats and stats['baseline_stdev'] > 0:
                        variance_ratio = agg_stats['stdev_ms'] / stats['baseline_stdev']
                        print(f"    Variance Increase: {variance_ratio:.2f}x baseline")

                stats['aggressive_mean'] = agg_stats.get('mean_ms', 0)
                stats['aggressive_stdev'] = agg_stats.get('stdev_ms', 0)
                stats['aggressive_success_rate'] = agg_stats.get('success_rate', 0)
                stats['aggressive_p95'] = agg_stats.get('p95_ms', 0)
                stats['aggressive_p99'] = agg_stats.get('p99_ms', 0)
                stats['aggressive_max'] = agg_stats.get('max_ms', 0)

        # Extreme stress test analysis (100 req/sec, 5000 requests)
        if 'extreme' in self.data:
            print(f"\n[*] Extreme Stress Test (100 req/sec, 5000 requests):")
            extreme_metrics = self.data['extreme'].get('metrics', [])

            if extreme_metrics:
                ext_stats = self._calculate_stats_from_metrics(extreme_metrics)

                print(f"    Total Requests Attempted: 5000")
                print(f"    Completed Requests: {ext_stats.get('total_count', 0)}")
                print(f"    Success Rate: {ext_stats.get('success_rate', 0):.1f}%")
                print(f"    Mean Response Time: {ext_stats.get('mean_ms', 0):.2f} ms")
                print(f"    Median Response Time: {ext_stats.get('median_ms', 0):.2f} ms")
                print(f"    Std Deviation: {ext_stats.get('stdev_ms', 0):.2f} ms")
                print(f"    Min: {ext_stats.get('min_ms', 0):.2f} ms")
                print(f"    Max: {ext_stats.get('max_ms', 0):.2f} ms")
                print(f"    P95: {ext_stats.get('p95_ms', 0):.2f} ms")
                print(f"    P99: {ext_stats.get('p99_ms', 0):.2f} ms")

                # Calculate degradation vs baseline
                if 'baseline_mean_response' in stats and stats['baseline_mean_response'] > 0:
                    ext_increase = ((ext_stats['mean_ms'] - stats['baseline_mean_response']) / stats['baseline_mean_response']) * 100
                    print(f"    Performance Degradation: {ext_increase:+.1f}% vs baseline")

                    # Variance ratio
                    if 'baseline_stdev' in stats and stats['baseline_stdev'] > 0:
                        variance_ratio = ext_stats['stdev_ms'] / stats['baseline_stdev']
                        print(f"    Variance Increase: {variance_ratio:.2f}x baseline")

                # Calculate timeout rate
                timeout_count = ext_stats.get('total_count', 0) - ext_stats.get('success_count', 0)
                if ext_stats.get('total_count', 0) > 0:
                    timeout_rate = (timeout_count / ext_stats.get('total_count', 0)) * 100
                    print(f"    Timeout Count: {timeout_count}")
                    print(f"    Timeout Rate: {timeout_rate:.1f}%")

                stats['extreme_mean'] = ext_stats.get('mean_ms', 0)
                stats['extreme_stdev'] = ext_stats.get('stdev_ms', 0)
                stats['extreme_success_rate'] = ext_stats.get('success_rate', 0)
                stats['extreme_p95'] = ext_stats.get('p95_ms', 0)
                stats['extreme_p99'] = ext_stats.get('p99_ms', 0)
                stats['extreme_max'] = ext_stats.get('max_ms', 0)
                stats['extreme_completed'] = ext_stats.get('total_count', 0)
                stats['extreme_timeout_count'] = timeout_count
            else:
                print(f"    Status: Test failed or timed out with no data")
                print(f"    Note: Server likely crashed immediately or test was terminated")
                stats['extreme_failed'] = True

        # WAF bypass analysis
        if 'waf_bypass' in self.data:
            waf_results = self.data['waf_bypass'].get('results', [])
            summary = self.data['waf_bypass'].get('summary', {})

            successful = summary.get('successful_bypasses', 0)
            blocked = summary.get('blocked', 0)
            total = len(waf_results)

            stats['waf_bypass_count'] = successful
            stats['waf_total_techniques'] = total
            stats['waf_bypass_rate'] = (successful / total * 100) if total > 0 else 0

            print(f"\n[*] WAF Bypass Analysis:")
            print(f"    Total Techniques Tested: {total}")
            print(f"    Successful Bypasses: {successful}")
            print(f"    Blocked: {blocked}")
            print(f"    Bypass Rate: {stats['waf_bypass_rate']:.1f}%")

            print(f"\n[*] Successful Bypass Techniques:")
            for result in waf_results:
                if result.get('execution_success') and not result.get('blocked_by_waf'):
                    print(f"    ✓ {result['technique']}")

        # Summary for paper
        print("\n" + "="*60)
        print(" COPY THESE VALUES TO YOUR PAPER")
        print("="*60)

        print(f"\nAbstract/Introduction:")
        if 'payload_size' in stats:
            print(f"  - Payload size: {stats['payload_size']} bytes ({stats['payload_size']/1024:.1f} KB)")
        if 'high_rate_increase' in stats:
            print(f"  - Response time increase: {stats['high_rate_increase']:.1f}% at high rate")
        if 'waf_bypass_count' in stats and 'waf_total_techniques' in stats:
            print(f"  - WAF bypass: {stats['waf_bypass_count']} out of {stats['waf_total_techniques']} techniques successful")

        print(f"\nTable 1 (Baseline Metrics):")
        if 'baseline_mean_response' in stats:
            print(f"  Mean Response Time: {stats['baseline_mean_response']:.2f} ms")
        if 'baseline_stdev' in stats:
            print(f"  Standard Deviation: {stats['baseline_stdev']:.2f} ms")
        if 'payload_size' in stats:
            print(f"  Payload Size: {stats['payload_size']} bytes")
        if 'baseline_success_rate' in stats:
            print(f"  Success Rate: {stats['baseline_success_rate']:.1f}%")

        print("\n" + "="*60 + "\n")

        return stats

    def generate_graphs(self):
        """Generate publication-quality graphs"""
        if not HAS_MATPLOTLIB:
            print("[!] Skipping graph generation (matplotlib not installed)")
            return

        print("[*] Generating graphs...")

        # Save graphs in the same directory as the script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        graphs_dir = os.path.join(script_dir, "paper_figures")
        if not os.path.exists(graphs_dir):
            os.makedirs(graphs_dir)

        # Graph 1: Response time comparison
        if all(k in self.data for k in ['low_rate', 'medium_rate', 'high_rate']):
            self._plot_response_time_comparison(graphs_dir)

        # Graph 2: Response time distribution
        if 'aggressive' in self.data:
            self._plot_response_time_distribution(graphs_dir)
        elif 'high_rate' in self.data:
            self._plot_response_time_distribution(graphs_dir)

        # Graph 3: Success rate by request rate
        if all(k in self.data for k in ['low_rate', 'medium_rate', 'high_rate']):
            self._plot_success_rates(graphs_dir)

        # Graph 4: WAF bypass results
        if 'waf_bypass' in self.data:
            self._plot_waf_bypass(graphs_dir)

        print(f"[+] Graphs saved to {graphs_dir}/")

    def _plot_response_time_comparison(self, output_dir):
        """Compare response times across different rates"""
        rates = ['low_rate', 'medium_rate', 'high_rate']
        labels = ['Low\n(1 req/s)', 'Medium\n(5 req/s)', 'High\n(20 req/s)']
        colors = ['green', 'orange', 'red']
        means = []
        stdevs = []

        for rate in rates:
            rt = self.data[rate].get('analysis', {}).get('response_times', {})
            means.append(rt.get('mean_ms', 0))
            stdevs.append(rt.get('stdev_ms', 0))

        # Add aggressive test if available
        if 'aggressive' in self.data:
            aggressive_metrics = self.data['aggressive'].get('metrics', [])
            if aggressive_metrics:
                agg_stats = self._calculate_stats_from_metrics(aggressive_metrics)
                rates.append('aggressive')
                labels.append('Aggressive\n(100 req/s)')
                means.append(agg_stats.get('mean_ms', 0))
                stdevs.append(agg_stats.get('stdev_ms', 0))
                colors.append('darkred')

        # Add extreme test if available and has data
        if 'extreme' in self.data:
            extreme_metrics = self.data['extreme'].get('metrics', [])
            if extreme_metrics:
                ext_stats = self._calculate_stats_from_metrics(extreme_metrics)
                # Only add if we have successful requests
                if ext_stats.get('success_count', 0) > 0:
                    rates.append('extreme')
                    labels.append('Extreme\n(100 req/s, 5K)')
                    means.append(ext_stats.get('mean_ms', 0))
                    stdevs.append(ext_stats.get('stdev_ms', 0))
                    colors.append('crimson')

        fig, ax = plt.subplots(figsize=(14, 6))
        x = range(len(labels))

        ax.bar(x, means, yerr=stdevs, capsize=5, alpha=0.7, color=colors)
        ax.set_xlabel('Request Rate', fontsize=12)
        ax.set_ylabel('Mean Response Time (ms)', fontsize=12)
        ax.set_title('Response Time vs Request Rate', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.grid(axis='y', alpha=0.3)

        # Add value labels on bars
        for i, (mean, stdev) in enumerate(zip(means, stdevs)):
            ax.text(i, mean + stdev + 2, f'{mean:.1f}ms',
                   ha='center', va='bottom', fontsize=9, fontweight='bold')

        plt.tight_layout()
        plt.savefig(f"{output_dir}/response_time_comparison.png", dpi=300)
        plt.close()

        print(f"[+] Generated: response_time_comparison.png")

    def _plot_response_time_distribution(self, output_dir):
        """Plot response time distribution histogram"""
        # Prefer aggressive data, fallback to high_rate
        if 'aggressive' in self.data:
            metrics = self.data['aggressive'].get('metrics', [])
            title = 'Response Time Distribution - Aggressive Stress Test (100 req/s)'
        else:
            metrics = self.data['high_rate'].get('metrics', [])
            title = 'Response Time Distribution - High Rate Attack (20 req/s)'

        response_times = [m['response_time_ms'] for m in metrics if m['response_time_ms'] > 0]

        if not response_times:
            return

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.hist(response_times, bins=50, alpha=0.7, color='steelblue', edgecolor='black')
        ax.set_xlabel('Response Time (ms)', fontsize=12)
        ax.set_ylabel('Frequency', fontsize=12)
        ax.set_title(title, fontsize=14, fontweight='bold')

        mean_time = statistics.mean(response_times)
        median_time = statistics.median(response_times)
        p95_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else max(response_times)
        p99_time = statistics.quantiles(response_times, n=100)[98] if len(response_times) >= 100 else max(response_times)

        ax.axvline(mean_time, color='red', linestyle='--', linewidth=2,
                   label=f'Mean: {mean_time:.1f}ms')
        ax.axvline(median_time, color='green', linestyle='--', linewidth=2,
                   label=f'Median: {median_time:.1f}ms')
        ax.axvline(p95_time, color='orange', linestyle=':', linewidth=1.5,
                   label=f'P95: {p95_time:.1f}ms')
        ax.axvline(p99_time, color='darkred', linestyle=':', linewidth=1.5,
                   label=f'P99: {p99_time:.1f}ms')

        ax.legend(fontsize=10)
        ax.grid(axis='y', alpha=0.3)

        plt.tight_layout()
        plt.savefig(f"{output_dir}/response_time_distribution.png", dpi=300)
        plt.close()

        print(f"[+] Generated: response_time_distribution.png")

    def _plot_success_rates(self, output_dir):
        """Plot success rates across different request rates"""
        rates = ['low_rate', 'medium_rate', 'high_rate']
        labels = ['Low\n(1 req/s)', 'Medium\n(5 req/s)', 'High\n(20 req/s)']
        success_rates = []

        for rate in rates:
            sr = self.data[rate].get('analysis', {}).get('success_rate', 0)
            success_rates.append(sr)

        # Add aggressive test if available
        if 'aggressive' in self.data:
            aggressive_metrics = self.data['aggressive'].get('metrics', [])
            if aggressive_metrics:
                agg_stats = self._calculate_stats_from_metrics(aggressive_metrics)
                labels.append('Aggressive\n(100 req/s)')
                success_rates.append(agg_stats.get('success_rate', 0))

        # Add extreme test if available and has data
        if 'extreme' in self.data:
            extreme_metrics = self.data['extreme'].get('metrics', [])
            if extreme_metrics:
                ext_stats = self._calculate_stats_from_metrics(extreme_metrics)
                if ext_stats.get('total_count', 0) > 0:
                    labels.append('Extreme\n(100 req/s, 5K)')
                    success_rates.append(ext_stats.get('success_rate', 0))

        fig, ax = plt.subplots(figsize=(14, 6))
        colors = ['green' if sr > 90 else 'orange' if sr > 70 else 'red' for sr in success_rates]

        bars = ax.bar(labels, success_rates, color=colors, alpha=0.7, edgecolor='black')
        ax.set_ylabel('Success Rate (%)', fontsize=12)
        ax.set_xlabel('Request Rate', fontsize=12)
        ax.set_title('Exploit Success Rate vs Request Rate', fontsize=14, fontweight='bold')
        ax.set_ylim([0, 105])
        ax.axhline(y=100, color='gray', linestyle='--', alpha=0.5)
        ax.grid(axis='y', alpha=0.3)

        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 1,
                   f'{height:.1f}%', ha='center', va='bottom', fontweight='bold')

        plt.tight_layout()
        plt.savefig(f"{output_dir}/success_rates.png", dpi=300)
        plt.close()

        print(f"[+] Generated: success_rates.png")

    def _plot_waf_bypass(self, output_dir):
        """Plot WAF bypass results"""
        results = self.data['waf_bypass'].get('results', [])

        if not results:
            return

        techniques = [r['technique'].replace(' ', '\n') for r in results]
        successes = [1 if (r['execution_success'] and not r['blocked_by_waf']) else 0 for r in results]
        colors = ['green' if s == 1 else 'red' for s in successes]

        fig, ax = plt.subplots(figsize=(12, 6))
        bars = ax.bar(range(len(techniques)), successes, color=colors, alpha=0.7, edgecolor='black')
        ax.set_ylabel('Bypass Successful', fontsize=12)
        ax.set_xlabel('Technique', fontsize=12)
        ax.set_title('WAF Bypass Technique Effectiveness', fontsize=14, fontweight='bold')
        ax.set_xticks(range(len(techniques)))
        ax.set_xticklabels(techniques, rotation=45, ha='right', fontsize=9)
        ax.set_ylim([0, 1.2])
        ax.set_yticks([0, 1])
        ax.set_yticklabels(['Failed', 'Success'])
        ax.grid(axis='y', alpha=0.3)

        plt.tight_layout()
        plt.savefig(f"{output_dir}/waf_bypass_results.png", dpi=300)
        plt.close()

        print(f"[+] Generated: waf_bypass_results.png")

    def generate_latex_tables(self):
        """Generate LaTeX table code ready to paste into paper"""
        print("\n" + "="*60)
        print(" LATEX TABLE CODE FOR PAPER")
        print("="*60)

        # Table 1: Baseline metrics
        if 'low_rate' in self.data:
            print("\n% Table 1: Baseline Performance Metrics")
            print("\\begin{table}[h]")
            print("\\centering")
            print("\\caption{Baseline Exploit Performance Metrics}")
            print("\\label{tab:baseline}")
            print("\\begin{tabular}{@{}lc@{}}")
            print("\\toprule")
            print("Metric & Value \\\\")
            print("\\midrule")

            analysis = self.data['low_rate'].get('analysis', {})
            rt = analysis.get('response_times', {})

            print(f"Mean Response Time & {rt.get('mean_ms', 0):.2f} ms \\\\")
            print(f"Standard Deviation & {rt.get('stdev_ms', 0):.2f} ms \\\\")
            print(f"Payload Size & {analysis.get('payload_size_bytes', 0)} bytes \\\\")
            print(f"Success Rate & {analysis.get('success_rate', 0):.1f}\\% \\\\")

            print("\\bottomrule")
            print("\\end{tabular}")
            print("\\end{table}")

        # Table 2: DoS threshold
        if all(k in self.data for k in ['low_rate', 'medium_rate', 'high_rate']):
            print("\n% Table 2: DoS Threshold Analysis")
            print("\\begin{table}[h]")
            print("\\centering")
            print("\\caption{DoS Threshold Analysis}")
            print("\\label{tab:dos}")
            print("\\begin{tabular}{@{}lcc@{}}")
            print("\\toprule")
            print("Request Rate & Server Response & Availability \\\\")
            print("\\midrule")

            low_sr = self.data['low_rate'].get('analysis', {}).get('success_rate', 0)
            med_sr = self.data['medium_rate'].get('analysis', {}).get('success_rate', 0)
            high_sr = self.data['high_rate'].get('analysis', {}).get('success_rate', 0)

            low_status = "Normal" if low_sr > 95 else "Degraded"
            med_status = "Normal" if med_sr > 95 else "Degraded" if med_sr > 80 else "Severe"
            high_status = "Normal" if high_sr > 95 else "Degraded" if high_sr > 80 else "Severe"

            print(f"1 req/sec & {low_status} & {low_sr:.1f}\\% \\\\")
            print(f"5 req/sec & {med_status} & {med_sr:.1f}\\% \\\\")
            print(f"20 req/sec & {high_status} & {high_sr:.1f}\\% \\\\")

            print("\\bottomrule")
            print("\\end{tabular}")
            print("\\end{table}")

        print("\n" + "="*60 + "\n")


def main():
    analyzer = ResultsAnalyzer()

    if not analyzer.load_all_data():
        sys.exit(1)

    # Generate all analysis
    analyzer.generate_paper_statistics()
    analyzer.generate_latex_tables()
    analyzer.generate_graphs()

    print("\n[+] Analysis complete!")

if __name__ == "__main__":
    main()
