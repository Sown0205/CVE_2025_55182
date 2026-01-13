<h1 align="center"> CVE-2025-55182 (React2Shell): Proof-of-Concept Demonstration & Benchmark Experiment </h1>

**<div align="center">Authors:** Bui Thai Son - s4037172, Nguyen Ngoc Dung - s3978535 and Tran Dinh Hai - s4041605

**Date:** January 12, 2026

</div>

## Overview

This repository contains a proof-of-concept demonstration and experimental analysis of CVE-2025-55182 (React2Shell), a critical deserialization-based remote code execution (RCE) vulnerability affecting React Server Functions and Next.js applications. The vulnerability exploits insufficient validation in the React Flight Protocol's chunk resolution mechanism, enabling prototype chain traversal and arbitrary code execution through malicious thenable objects.

## 1. Practical Demonstration: Step-by-Step Exploitation

To demonstrate the real-world applicability of this vulnerability, we conducted a practical demonstration following responsible security testing guidelines in a controlled environment.

### Prerequisites and Setup

This repository includes a test Next.js default server with a vulnerable version (16.0.6). The demonstration shows the sequence to exercise the vulnerable path in a lab environment.

**Prerequisites:**
- Node.js environment compatible with the vulnerable framework version
- A local test app or instrumented handler that accepts Flight Protocol-style multipart chunk input
- A non-production or sandbox environment (VM/container) with no network access to sensitive systems

**Environment Setup:**

The test server folder contains an example Next.js layout used during vulnerability research. All demonstrations were conducted in an isolated environment with no external network connectivity.

### Step-by-Step Demonstration

**Step 1: Server Initialization**

First, we start the server in a controlled/sandbox environment:

```powershell
# from repo root
cd test-server
npm install
npm run dev
```

Upon loading the server, a very simple page appears:

![Next.js default app](screenshots/next.js-app.png)

This confirms the Next.js application is running correctly and ready to accept requests.

**Step 2: Payload Preparation**

Return to the root folder and navigate to the demo directory:

```bash
cd ../demo
```

The `poc.py` PoC script contains the crafted payload that exploits prototype pollution to gain access to Node.js internals and execute arbitrary code. For demonstration purposes, we execute non-destructive information commands.

**Step 3: Basic Exploitation - User Information Retrieval**

Execute the `whoami` command to retrieve server user information:

```python
python poc.py http://localhost:3000 "whoami"
```

This returns the server's `whoami` information, confirming successful code execution:

![poc.png](screenshots/poc.png)

**Step 4: Alternative Non-Destructive Commands**

Other executable, non-destructive commands that can be demonstrated:

- `id` - Display user identity (Unix/Linux)
- `calc` - Open calculator program (Windows) - classic PoC demonstration
- `echo "pwned"` - Simple output verification
- `ls` - Directory listing

**Step 5: Calculator Launch Demonstration**

Open the calculator program on target server (classic PoC demonstration):

```python
python poc.py http://localhost:3000 calc
```

![poc2.png](screenshots/poc2.png)

This demonstrates GUI application launching capability, a common proof-of-concept technique that visually confirms code execution without system damage.

**Step 6: System Information Extraction**

Display full system information of the target server (Windows environment):

```python
python poc.py http://localhost:3000 systeminfo
```

![poc3.png](screenshots/poc3.png)

This demonstrates the attacker's ability to perform reconnaissance and gather detailed system configuration data.

#### Quick Demonstration Video

![Quick demo hehe](screenshots/poc_demo-ezgif.com-optimize.gif)

The animated demonstration shows the complete exploitation workflow from payload delivery to command execution.

### Expected Results in Vulnerable Environment

- The server's deserialization flow calls attacker-supplied code before action validation occurs
- Command output is embedded in error messages or responses
- Successful exploitation is indicated by HTTP 500 status codes with command output in the error digest

### Responsible Testing Guidelines

**Commands that should be avoided:**

- **Shutdown/reboot commands**: `shutdown -s -t 0` (Windows), `reboot` (Linux/Mac)
- **Process controls**: Commands that terminate or manipulate system processes
- **Network exfiltration**: Commands that transmit data to external systems
- **Package manager/installer**: Commands that install or modify system packages
- **Any destructive commands**: Operations that modify, delete, or corrupt data

**Important Notes:**

1. Always test in isolated environments with no external network connectivity
2. Replace destructive payload actions with harmless side-effects (e.g., write to a temp file or emit a log) when developing proofs-of-concept
3. Never test against production systems or systems you do not own
4. Obtain explicit written permission before conducting any security testing
5. Document all testing activities for audit purposes

This practical demonstration confirms that the vulnerability can be reliably exploited with minimal technical barriers.


## 2. Why Proof-of-Concept Experimentation?

While the demonstration in Section 1 confirms the vulnerability is exploitable, comprehensive PoC experimentation serves several critical purposes beyond basic validation:

### Understanding Real-World Impact

**Performance Characterization**: Basic PoC demonstrations show that a vulnerability works, but don't reveal how it behaves under realistic conditions. Our experimental framework tested the exploit under various load scenarios (1, 5, 20, and 100 requests/second) with different request volumes (50 to 5,000 requests) to understand:
- How reliably the exploit works across different server loads
- Whether exploitation becomes less reliable under stress
- What performance degradation patterns emerge during sustained attacks
- Whether the vulnerability has dual-use potential (RCE + DoS)

**Threat Modeling**: Organizations need concrete data to assess risk. Knowing that:
- The exploit maintains 100% success rate across 7,351 attempts
- Response times remain consistent (80-99ms mean) even under extreme load
- The server experiences 11.4× slowdown under sustained attack
- Maximum response times can reach 2.26 seconds during saturation

...provides security teams with quantifiable metrics for prioritizing patching efforts and understanding attack sustainability.

### Security Research Contributions

**Reproducibility**: Our automated experimentation framework (`experiment/` directory) allows other researchers to:
- Validate our findings independently
- Test mitigations and defensive measures
- Compare exploit behavior across different environments
- Build upon our methodology for studying similar vulnerabilities

**Statistical Rigor**: Unlike anecdotal demonstrations, our experiments provide:
- Large sample sizes (7,381 total requests) for statistical significance
- Controlled variables (request rate, payload type, load scenario)
- Comprehensive metrics (mean, median, standard deviation, percentiles)
- Comparative analysis across multiple conditions

### Mitigation Development

**Detection Strategy Design**: Understanding exploit behavior patterns enables:
- Identifying reliable detection signatures
- Determining baseline vs. anomalous behavior
- Designing IDS/IPS rules with low false positive rates
- Creating behavioral detection mechanisms

**Defense-in-Depth Planning**: Performance data helps organizations:
- Calculate acceptable request rate limits
- Size infrastructure to handle attack volumes
- Design graceful degradation strategies
- Plan incident response procedures

### Ethical Considerations

All experimentation was conducted:
- In isolated test environments with no external connectivity
- On locally controlled infrastructure
- Following responsible disclosure principles
- With focus on defense and mitigation, not attack optimization

The experimental data in the `experiment/` directory demonstrates how security research can be conducted ethically while providing maximum value to the security community.

## 3. Experimental Results

### 3.1 Experiment 1: Basic Functionality Verification

**Objective**: Verify that the exploit successfully executes arbitrary commands on the target server.

**Results**:
- **Execution Time**: 3.85 seconds
- **Response Status**: 500 (Internal Server Error - indicates exploit success)
- **Response Time**: 2918.85ms
- **Payload Size**: 422 bytes
- **Success**: ✓ Confirmed

The initial test successfully executed the `whoami` command on the target server, confirming the viability of the exploitation technique. The server returned a 500 error with the command output embedded in the error digest, demonstrating that arbitrary code execution was achieved.

**Key Observation**: The exploit works as designed with minimal resource requirements (422-byte payload) and executes within acceptable time constraints for an attacker.

### 3.2 Experiment 2: Low-Rate Performance Analysis (1 req/sec)

**Objective**: Establish baseline performance metrics under ideal, low-load conditions.

**Parameters**:
- Total Requests: 50
- Request Rate: 1 request/second
- Command: `whoami`
- Total Duration: 53.77 seconds

**Results Summary**:

| Metric | Value |
|--------|-------|
| Successful Exploits | 50/50 (100%) |
| Failed Attempts | 0 |
| Mean Response Time | 74.69 ms |
| Median Response Time | 71.46 ms |
| Min Response Time | 58.12 ms |
| Max Response Time | 112.11 ms |
| Standard Deviation | 11.06 ms |
| Payload Size | 422 bytes |

**Analysis**:

The low-rate test established a baseline for exploit performance. Key findings:

1. **Perfect Reliability**: 100% success rate indicates the exploit is deterministic and not subject to race conditions or timing issues
2. **Consistent Performance**: Low standard deviation (σ = 11.06ms) shows predictable behavior
3. **Fast Execution**: Mean response time of 74.69ms is well within typical HTTP request latency
4. **Minimal Variance**: The interquartile range (IQR) is narrow, suggesting stable server behavior

The response time distribution follows an approximately normal distribution with slight right skew, likely due to garbage collection or other Node.js runtime factors.

### 3.3 Experiment 3: Medium-Rate Performance Analysis (5 req/sec)

**Objective**: Evaluate performance degradation under moderate concurrent load.

**Parameters**:
- Total Requests: 100
- Request Rate: 5 requests/second (200ms inter-request delay)
- Command: `whoami`
- Total Duration: 28.43 seconds

**Results Summary**:

| Metric | Value | Change from Baseline |
|--------|-------|---------------------|
| Successful Exploits | 100/100 (100%) | 0% |
| Failed Attempts | 0 | 0 |
| Mean Response Time | 71.72 ms | -3.98% |
| Median Response Time | 70.88 ms | -0.81% |
| Min Response Time | 57.79 ms | -0.57% |
| Max Response Time | 113.01 ms | +0.80% |
| Standard Deviation | 8.53 ms | -22.88% |
| Payload Size | 422 bytes | 0% |

**Analysis**:

Surprisingly, medium-rate testing showed *improved* performance compared to baseline:

1. **Maintained Reliability**: 100% success rate demonstrates robustness under concurrent load
2. **Reduced Latency**: Mean response time decreased by ~4%, possibly due to:
   - JIT compiler optimizations after repeated execution
   - Connection pooling and keep-alive effects
   - Cache warming of Node.js modules
3. **Lower Variance**: 23% reduction in standard deviation indicates more consistent server behavior under sustained load
4. **No Saturation**: The server handled 5 req/sec without resource exhaustion

This suggests the vulnerability exploitation is computationally inexpensive for the server, making it difficult to detect through performance monitoring alone.

### 3.4 Experiment 4: High-Rate Stress Testing (20 req/sec)

**Objective**: Determine system behavior under high load and potential for denial-of-service.

**Parameters**:
- Total Requests: 200
- Request Rate: 20 requests/second (50ms inter-request delay)
- Command: `whoami`
- Total Duration: 27.21 seconds

**Results Summary**:

| Metric | Value | Change from Baseline |
|--------|-------|---------------------|
| Successful Exploits | 200/200 (100%) | 0% |
| Failed Attempts | 0 | 0 |
| Mean Response Time | 76.40 ms | +2.29% |
| Median Response Time | 74.87 ms | +4.77% |
| Min Response Time | 55.54 ms | -4.44% |
| Max Response Time | 101.59 ms | -9.38% |
| Standard Deviation | 9.91 ms | -10.41% |
| Payload Size | 422 bytes | 0% |

**Analysis**:

Even under aggressive load (20 req/sec), the vulnerability exploitation remained highly reliable:

1. **Undiminished Success**: 100% success rate across 200 consecutive requests
2. **Minimal Degradation**: Only 2.3% increase in mean response time despite 20× higher load
3. **Consistent Behavior**: Standard deviation remained low (9.91ms), indicating stable exploitation
4. **No Server Failure**: No timeouts, crashes, or error responses observed
5. **Reduced Peak Latency**: Maximum response time actually *decreased*, possibly due to optimized resource scheduling under load

**DoS Assessment**: While the exploit itself doesn't cause service disruption at this rate, the server maintained perfect functionality. However, this represents a moderate load scenario; higher rates were tested to identify the breaking point.

### 3.5 Experiment 5: Aggressive Stress Testing (100 req/sec, 2000 requests)

**Objective**: Evaluate server behavior and exploitation reliability under sustained aggressive load to identify performance degradation patterns and stress thresholds.

**Parameters**:
- Total Requests: 2,000
- Request Rate: 100 requests/second (10ms inter-request delay)
- Command: `whoami`
- Expected Duration: ~20 seconds
- Actual Duration: 197.55 seconds

**Results Summary**:

| Metric | Value | Change from Baseline |
|--------|-------|---------------------|
| Successful Exploits | 2000/2000 (100%) | 0% |
| Failed Attempts | 0 | 0 |
| Mean Response Time | 84.51 ms | +13.1% |
| Median Response Time | 82.66 ms | +15.7% |
| Min Response Time | 52.80 ms | -9.1% |
| Max Response Time | 196.52 ms | +75.3% |
| Standard Deviation | 12.25 ms | +10.8% |
| P95 (95th percentile) | 102.57 ms | N/A |
| P99 (99th percentile) | 123.82 ms | N/A |
| Payload Size | 422 bytes | 0% |

**Critical Observations**:

1. **Perfect Reliability Maintained**: Despite aggressive load (100 req/sec), all 2,000 requests succeeded, demonstrating deterministic exploitation even under extreme stress

2. **Server Saturation Confirmed**: Actual execution took 197.5 seconds instead of expected 20 seconds (~10× slower), indicating severe resource contention and event loop saturation

3. **Variance Increase**: Standard deviation increased from 8.96ms (baseline) to 12.25ms, representing a **36.7% increase in variance** - clear indicator of stressed server behavior

4. **Tail Latency Degradation**:
   - P95: 102.57ms (slower than 95% of requests)
   - P99: 123.82ms (slower than 99% of requests)
   - Max: 196.52ms (**2.3× the mean** - severe tail latency)
   - This demonstrates that while mean performance appears acceptable, worst-case scenarios show significant degradation

5. **Response Time Distribution**:
   - Range expanded from ~54ms (baseline) to 143.7ms (aggressive)
   - Coefficient of variation increased from 12% to 14.5%
   - Distribution shows clear right skew, indicating occasional severe delays

**Performance Degradation Analysis**:

The aggressive stress test revealed critical performance characteristics:

- **Mean Response Time**: +13.1% increase suggests moderate average impact
- **Variance Pattern**: 36.7% variance increase indicates **loss of predictability**
- **Tail Behavior**: Max response time 2.3× mean shows **resource contention**
- **Duration Anomaly**: 10× expected duration proves **event loop saturation**

**Statistical Distribution**:

The response time distribution shows:
- Tight clustering around 80-85ms (most requests)
- Long right tail extending to 196ms (outliers under stress)
- Clear multimodal characteristics suggesting different execution paths under load

**Key Finding**: At 100 req/sec sustained rate, the server remains functional but exhibits clear signs of saturation:
- All requests eventually succeed (no crashes)
- Response times remain relatively stable (mean ~85ms)
- But variance increases significantly (12.25ms vs 8.96ms baseline)
- And tail latencies show 2-3× slowdown for unlucky requests

This represents the **stress threshold** - the server is pushed to its limits but not beyond breaking point.

### 3.6 Experiment 6: Extreme Stress Testing (100 req/sec, 5000 requests)

**Objective**: Determine complete failure threshold and confirm denial-of-service potential.

**Parameters**:
- Total Requests: 5,000
- Request Rate: 100 requests/second (10ms inter-request delay)
- Command: `whoami`
- Expected Duration: ~50 seconds
- Global Timeout Threshold: 20 minutes (1200 seconds)

**Results**:

| Metric | Value |
|--------|-------|
| Status | **SUCCESS** |
| Actual Execution Time | 569.57 seconds (9.5 minutes) |
| Requests Attempted | 5,000 |
| Requests Completed | 5,000 |
| Success Rate | 100.0% |
| Mean Response Time | 99.42ms |
| Median Response Time | 96.03ms |
| Std Dev | 46.78ms |
| Min Response Time | 35.38ms |
| Max Response Time | 2256.04ms (2.26 seconds) |
| P95 Response Time | ~180ms (estimated) |
| P99 Response Time | ~500ms (estimated) |

**Understanding the Timeout Behavior**:

This experiment reveals critical insights about server saturation under sustained exploit load:

1. **Why 5-Minute Timeout Failed**:
   - Initial test configuration used 300-second (5-minute) global timeout
   - Server required ~569 seconds (9.5 minutes) to complete all 5,000 requests
   - Test was terminated prematurely by the global timeout mechanism
   - No data was collected because the entire process was killed

2. **Why 20-Minute Timeout Succeeded**:
   - Extended global timeout to 1200 seconds (20 minutes)
   - Gave server sufficient time to process all requests despite severe slowdown
   - All 5,000 requests completed successfully with 100% success rate
   - Collected complete performance metrics showing server degradation patterns

3. **Two-Level Timeout System**:
   - **Per-request timeout**: 10 seconds (handles individual slow requests gracefully)
   - **Global timeout**: 1200 seconds (prevents entire test from hanging indefinitely)
   - Individual timeouts are recorded as data points, not failures
   - Global timeout only triggers if the entire test exceeds the threshold

4. **Server Performance Degradation**:
   - Expected duration: 50 seconds (at nominal performance)
   - Actual duration: 569 seconds (9.5 minutes)
   - **Performance degradation ratio**: 11.4× slower than expected
   - Server remained functional but severely degraded under sustained load

**Analysis**:

The extreme stress test definitively demonstrates **severe performance degradation and DoS potential**:

1. **Server Saturation Evidence**:
   - Server took 11.4× longer than expected to complete all requests
   - Event loop severely saturated but not completely blocked
   - Response time variance increased dramatically (std dev: 46.78ms vs baseline ~14ms)
   - Maximum response time reached 2.26 seconds (63× slower than mean)
   - Server remained technically responsive but practically unusable

2. **DoS Threshold Identified**:
   - 2,000 requests @ 100 req/sec: **Survives** (stressed but functional, 213s duration)
   - 5,000 requests @ 100 req/sec: **Severely Degraded** (570s duration, 11.4× slowdown)
   - **Critical threshold**: Between 2,000-5,000 sustained requests at this rate
   - Beyond this point, server performance degrades exponentially

3. **Attack Sustainability**:
   - An attacker could maintain 100 req/sec for 50 seconds (expected timeframe)
   - Server would require 9.5 minutes to recover from this 50-second attack
   - During recovery, legitimate users experience 2+ second response times
   - This constitutes a practical denial-of-service condition
   - No server restart required, but service quality is unacceptable

4. **Practical DoS Implications**:
   - Single attacker can cause sustained DoS with moderate bandwidth
   - No distributed attack needed (unlike traditional DDoS)
   - Exploits legitimate protocol features (bypasses rate limiting)
   - Service disruption is guaranteed and measurable (11.4× slowdown)
   - Detection window is limited (degradation happens within minutes)
   - Recovery time exceeds attack duration by 11× (asymmetric impact)

**Comparison: Stress vs Extreme**:

| Aspect | Experiment 5 (2K req) | Experiment 6 (5K req) |
|--------|----------------------|----------------------|
| Duration | 213s (completed) | 570s (9.5 minutes) |
| Expected Duration | ~20s | ~50s |
| Slowdown Factor | 10.6× | 11.4× |
| Success Rate | 100% | 100% |
| Mean Response Time | 91.50ms | 99.42ms |
| Max Response Time | 323.89ms | 2256.04ms (2.26s) |
| Std Dev | 19.65ms | 46.78ms |
| Server Status | Heavily Saturated | Severely Degraded |
| Recovery | Self-recovers | Self-recovers (slowly) |
| User Experience | Slow but usable | Practically unusable |
| Attack Viability | Stress testing | Practical DoS |

**Security Implication**: The vulnerability is not just an RCE vector - it's also a **reliable DoS attack** that can severely degrade Next.js application performance. While the server doesn't completely crash, the 11.4× slowdown and multi-second response times constitute a practical denial-of-service condition for legitimate users.

### 3.7 Comparative Performance Analysis

![Response Time Comparison](experiment/paper_figures/response_time_comparison.png)
*Figure 1: Mean response times across different request rates with standard deviation error bars*

The comparison across all six load scenarios reveals:

| Request Rate | Requests | Mean RT (ms) | Std Dev (ms) | P95 (ms) | P99 (ms) | Max (ms) | Success Rate | Notes |
|--------------|----------|--------------|--------------|----------|----------|----------|--------------|-------|
| 1 req/sec | 50 | 85.77 | 17.61 | N/A | N/A | 141.26 | 100% | Baseline |
| 5 req/sec | 100 | 80.09 | 14.14 | N/A | N/A | 122.91 | 100% | Optimal |
| 20 req/sec | 200 | 86.13 | 12.49 | N/A | N/A | 119.22 | 100% | Stable |
| 100 req/sec | 2,000 | 91.50 | 19.65 | ~110 | ~140 | 323.89 | 100% | **Stressed** |
| 100 req/sec | 5,000 | 99.42 | 46.78 | ~180 | ~500 | 2256.04 | 100% | **Severe DoS** |

**Key Insights**:

1. **Trimodal Behavior**: The server exhibits three distinct operational modes:
   - **Stable Zone** (1-20 req/sec): Consistent ~80-86ms mean, low variance (12-18ms std dev)
   - **Stress Zone** (100 req/sec, 2K requests): Elevated mean (91ms), moderate variance (19.65ms)
   - **Severe Degradation Zone** (100 req/sec, 5K requests): High mean (99ms), extreme variance (46.78ms), multi-second tail latencies

2. **Performance Cliff**: Between 20 and 100 req/sec exists a performance cliff where:
   - Mean response time increases 6-14%
   - Variance increases 57% (from 12.49ms to 19.65ms)
   - Tail latencies appear (P95, P99)
   - Event loop saturation becomes evident

3. **DoS Threshold Confirmed**: Between 2,000 and 5,000 requests at 100 req/sec, the server transitions from stressed to severely degraded:
   - 2,000 requests: 10.6× slowdown (213s vs 20s expected)
   - 5,000 requests: 11.4× slowdown (570s vs 50s expected)
   - Maximum response time jumps from 324ms to 2,256ms (7× increase)
   - Variance more than doubles (19.65ms → 46.78ms)

4. **Attack Implications**:
   - Below 20 req/sec: Stealthy reconnaissance possible (minimal performance impact)
   - At 100 req/sec (2K requests): Server heavily stressed but functional
   - At 100 req/sec (5K requests): Practical DoS achieved - server responds but is unusable
   - Recovery time exceeds attack duration by 11×

**Statistical Significance**: The variance increase from baseline (σ=17.61ms) to extreme (σ=46.78ms) represents a 165% relative increase, indicating severe server saturation. The maximum response time of 2.26 seconds (vs 141ms baseline) represents a 16× degradation in worst-case performance, making the service practically unusable for legitimate users.

### 3.8 Response Time Distribution Analysis

![Response Time Distribution](experiment/paper_figures/response_time_distribution.png)
*Figure 2: Histogram of response times during aggressive stress test (n=2,000)*

The response time distribution for the aggressive stress scenario (100 req/sec, 2,000 requests) reveals:

- **Unimodal distribution**: Primary peak around 80-85ms
- **Pronounced right skew**: Extended tail reaching 196ms
- **Core clustering**: ~70% of requests fall within ±10ms of median
- **Tail behavior**: Significant outliers (P95: 102.57ms, P99: 123.82ms, Max: 196.52ms)

**Distribution Characteristics**:

1. **Central Tendency**: Median (82.66ms) closely matches mean (84.51ms), indicating symmetric core
2. **Tail Latency**: Right tail extends to 2.3× the mean, showing resource contention effects
3. **Variance Pattern**: Most requests execute quickly, but ~5% experience significant delays
4. **Percentile Analysis**:
   - 50% of requests: ≤82.66ms (fast)
   - 95% of requests: ≤102.57ms (acceptable)
   - 99% of requests: ≤123.82ms (stressed)
   - Worst 1%: Up to 196.52ms (severe degradation)

**Practical Implications**:

The distribution characteristics indicate:
1. **No performance bifurcation**: Single code path, not dual-mode behavior
2. **Event loop contention**: Tail latencies caused by queue backlog, not GC pauses
3. **Predictable for 95% of cases**: Attackers can expect ~85ms execution for most requests
4. **Unpredictable extremes**: Occasional severe delays (2-3× normal) under sustained load

**Comparison with Baseline**:
- Baseline (1 req/sec): Tight distribution (σ=11.06ms), max=112ms
- Aggressive (100 req/sec): Wider distribution (σ=12.25ms), max=196ms
- **Spread increase**: 75% wider maximum, 36.7% variance increase

### 3.9 Success Rate Analysis

![Success Rates](experiment/paper_figures/success_rates.png)
*Figure 3: Exploit success rates across different load scenarios (includes aggressive 100 req/sec test)*

All six experiments achieved **100% success rate**, demonstrating:

1. **Deterministic Exploitation**: No race conditions or timing dependencies across 7,351 requests
2. **Robust Payload**: Works reliably from 1 req/sec to 100 req/sec across all load conditions
3. **Protocol-Level Vulnerability**: Not affected by application-level rate limiting or defensive measures
4. **Attack Reliability Under Extreme Stress**: Even with severe server saturation (570s actual vs 50s expected in extreme test), all requests eventually succeeded
5. **Load Independence**: Success rate remains 100% regardless of concurrent load, variance, tail latencies, or server degradation

**Critical Finding**: The vulnerability's reliability is independent of server stress. Even when:
- Response times increase 16% (mean)
- Maximum response times increase 16× (2,256ms vs 141ms baseline)
- Variance increases 165% (extreme saturation)
- Server duration extends 11.4× expected time (570s vs 50s)
- Multi-second response times occur (2.26s maximum)

...the exploit **still succeeds 100% of the time**. This makes it exceptionally dangerous as server stress does not provide natural protection against exploitation.

**DoS Boundary**: At extreme sustained load (5,000 requests @ 100 req/sec), the server experiences severe degradation with 11.4× slowdown and multi-second response times, representing the transition from "stressed but exploitable" to "practical denial of service" - the server remains technically responsive but is unusable for legitimate users.

### 3.10 Experiment 7: Payload Comparison Study

**Objective**: Analyze how different command types affect exploitation performance.

We tested four different commands to understand execution characteristics:

#### Test Case 1: `id` Command (Unix)
- **Total Requests**: 10
- **Success Rate**: 0% (command not available on Windows test environment)
- **Mean Response Time**: 58.87ms
- **Observation**: Payload delivery succeeded, but command execution failed due to OS incompatibility

#### Test Case 2: `whoami` Command
- **Total Requests**: 10
- **Success Rate**: 100%
- **Mean Response Time**: 85.34ms
- **Median Response Time**: 88.73ms
- **Standard Deviation**: 14.37ms
- **Observation**: Reliable execution with moderate variance

#### Test Case 3: `echo test` Command
- **Total Requests**: 10
- **Success Rate**: 100%
- **Mean Response Time**: 43.25ms
- **Median Response Time**: 42.35ms
- **Standard Deviation**: 13.35ms
- **Observation**: Fastest execution due to shell built-in command (no subprocess spawn)

#### Test Case 4: `systeminfo` Command (Complex)
- **Total Requests**: 10
- **Success Rate**: 100%
- **Mean Response Time**: 3522.37ms
- **Median Response Time**: 3585.13ms
- **Standard Deviation**: 140.58ms
- **Observation**: Significantly slower due to extensive system information gathering

**Command Performance Comparison**:

| Command | Mean RT (ms) | Success Rate | Relative Speed |
|---------|-------------|--------------|----------------|
| `echo test` | 43.25 | 100% | Baseline (fastest) |
| `whoami` | 85.34 | 100% | 1.97× slower |
| `systeminfo` | 3522.37 | 100% | 81.4× slower |
| `id` | 58.87 | 0%* | N/A |

*Failed due to OS compatibility, not exploit failure

**Key Findings**:

1. **Command Complexity Correlation**: Response time strongly correlates with command execution time, not exploitation overhead
2. **Shell Built-ins Faster**: Commands handled by the shell interpreter (`echo`) execute faster than spawned processes (`whoami`)
3. **Exploit Overhead Minimal**: Even the fastest command (43ms) shows that the exploitation adds minimal latency
4. **Payload Flexibility**: Attackers can execute arbitrary commands of any complexity with consistent reliability

## Security Impact & Mitigation

### Immediate Actions Required

**Priority 1: Upgrade to Patched Versions**

```bash
# For Next.js applications
npm install next@latest

# Verify version
npx next --version
# Should show 16.0.7 or higher
```

**Affected versions and fixes**:
- Next.js 14.x → 14.2.18 or higher
- Next.js 15.x → 15.1.2 or higher
- Next.js 16.x → 16.0.7 or higher
- React 19.x → 19.0.0 or higher (stable release)

**Priority 2: Temporary Mitigation (if immediate upgrade not possible)**

Implement WAF rules to block suspicious patterns:

```nginx
# Block requests with suspicious chunk patterns
location / {
    if ($request_body ~* "__proto__|constructor:constructor") {
        return 403;
    }
    proxy_pass http://nextjs_backend;
}
```

**Warning**: This is a temporary measure and can be bypassed. Upgrade as soon as possible.

### Defense-in-Depth Recommendations

1. **Sandboxing**: Run Next.js servers in containerized environments with minimal privileges
2. **Network Segmentation**: Isolate application servers from sensitive resources
3. **Input Validation**: Implement strict validation for Server Action inputs
4. **Rate Limiting**: Deploy request rate limiting to slow down mass exploitation
5. **Monitoring**: Enable logging and alerting for exploitation attempts

### Detection Signatures

Monitor logs for these patterns:
- `__proto__` in request bodies to Server Actions
- `constructor:constructor` references
- `execSync` and `child_process` in error messages
- Unusual subprocess spawning from Node.js processes

## Repository Structure

```
CVE_2025_55182/
├── demo/
│   └── poc.py                    # Basic PoC script for quick demonstration
├── experiment/
│   ├── poc_enhanced.py           # Enhanced PoC with metrics collection
│   ├── run_experiments.py        # Automated experiment orchestration
│   ├── analyze_results.py        # Statistical analysis scripts
│   └── paper_figures/            # Experimental result visualizations
├── test-server/                  # Vulnerable Next.js 16.0.6 test server
├── screenshots/                  # Demonstration screenshots and videos
└── README.md                     # This file
```

## Acknowledgments

Special thanks to:
- **React and Next.js teams** for responsible vulnerability handling and rapid patch development
- **Moritz Sanft (@msanft)** for initial discovery and analysis
- **Low Level (@LowLevelTV)** for demonstrating real-world implications
- **Security research community** for responsible disclosure practices

This research was conducted in accordance with responsible disclosure principles. All testing was performed in isolated, controlled environments without targeting production systems.

## References and Further Reading

- [React Security Advisory](https://react.dev/blog/2025/01/react-19-security-update)
- [Next.js Security Advisory](https://github.com/vercel/next.js/security/advisories/)
- [CVE-2025-55182 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-55182)
- [Original Discovery by Moritz Sanft](https://github.com/msanft/CVE-2025-55182)

---

**Contact Information**

For questions or additional information:
- Bui Thai Son - s4037172@rmit.edu.vn (PoC experiment Lead)
- Nguyen Ngoc Dung - s3978535@rmit.edu.vn
- Tran Dinh Hai - s4041605@rmit.edu.vn (Research Lead)

---
