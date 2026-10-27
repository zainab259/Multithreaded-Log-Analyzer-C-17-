# MultiLog Analyzer

MultiLog Analyzer is a C++17 command-line log scanner that parses Apache/Nginx combined access logs and a small documented application format, summarizes them, optionally flags configurable patterns, and can generate terminal, CSV, or JSON reports.

## Why it exists

Production log files can be too large to load into memory at once. This project demonstrates streaming file I/O, parsing, aggregation, synchronization, and practical C++ project organization in a portfolio-sized application.

## Features

- Streaming input in fixed-size batches; malformed lines are counted and skipped.
- Apache/Nginx combined access format and application format `YYYY-MM-DD HH:MM:SS LEVEL [IP] message`.
- Sequential or worker-pool processing, severity/IP/status/keyword filters.
- Counts, HTTP status classes, top IPs and URLs, error messages, requests per minute, and observed timestamp bounds.
- Optional time-window heuristic alerts for repeated 401/403, 404, 5xx, and high per-IP request volume.
- Terminal output and saved JSON/CSV reports under `reports/`.
- Benchmark mode for 1/2/4/8 workers, with configurable repetitions.
- GoogleTest unit tests, CTest integration, and opt-in ASan/TSan flags.

Metrics that do not apply to a format are omitted from maps or shown as unavailable in the terminal. The application does not treat missing HTTP metrics as zero HTTP traffic.

## Architecture

`LogParser` returns an optional structured `LogEntry`. `LogAnalyzer` streams lines into batches, parses each batch locally, then merges batch maps under one aggregation mutex. `ThreadPool` uses a bounded task queue, a condition variable for work and queue capacity, an atomic completed-task counter, and joins all workers on destruction. Worker exceptions are captured and rethrown by `wait()`. `SuspiciousActivityDetector` applies transparent thresholds to retained matched entries. `ReportGenerator` serializes the aggregate without requiring a JSON library.

Input lines are streamed, but matched valid entries are retained in memory for detector rules. Thus memory grows with matched entries; for very large files without detection, a future enhancement should allow disabling entry retention or use streaming detector state. Timestamped access requests use a configurable detector window (default five minutes). Timestamps in application logs have no timezone field and are treated as UTC. Apache offsets are currently parsed as UTC; non-UTC offsets are not adjusted.

## Requirements and build

Requires CMake 3.16+, a C++17 compiler, and (when tests are enabled) network access for CMake FetchContent to download GoogleTest 1.14. On Ubuntu/Kali:

```bash
sudo apt update
sudo apt install -y build-essential cmake git python3
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

To build without fetching test dependencies: `cmake -S . -B build -DMULTILOG_BUILD_TESTS=OFF`.
Sanitizers (supported compiler/platform required): `-DMULTILOG_ENABLE_ASAN=ON` or `-DMULTILOG_ENABLE_TSAN=ON`; they cannot be combined.

## Usage

```bash
./build/multilog --help
./build/multilog --file logs/sample.log
./build/multilog --file logs/sample.log --threads 4 --detect-suspicious
./build/multilog --file logs/sample.log --level ERROR
./build/multilog --file logs/sample.log --ip 192.0.2.10
./build/multilog --file logs/sample.log --status 404
./build/multilog --file logs/sample.log --from 2024-10-10T13:55:00 --to 2024-10-10T14:00:00
./build/multilog --file logs/sample.log --keyword database --output json
./build/multilog --file logs/sample.log --detect-suspicious --window-minutes 10
./build/multilog --file logs/sample.log --output csv
```

Reports are written to `reports/<input>_report.json` or `.csv`. Filters affect statistics and retained entries; total/valid/invalid indicate input and parsing counts before filtering. Only `.log` and `.txt` extensions are accepted.

## Generate benchmark data

```bash
python3 tools/generate_logs.py --count 10000 --output logs/10k.log
python3 tools/generate_logs.py --count 100000 --output logs/100k.log
python3 tools/generate_logs.py --count 1000000 --output logs/1m.log
./build/multilog --benchmark --file logs/100k.log --repetitions 3
```

Benchmark results are printed as CSV-like rows containing elapsed time, lines/second, and speedup against the single-worker run. No benchmark values are published here because results depend on the machine and have not been measured in this workspace.

## Example output

The sample file contains eight lines, seven parseable entries, and includes one malformed line. Exact timing and throughput vary by machine:

```text
MultiLog Analyzer
Entries: 8 | valid: 7 | invalid: 1 | matched: 7
Severity: ERROR=2 INFO=2 WARNING=3
HTTP classes: 2xx=1 4xx=3 5xx=1
Time range: 2024-10-10 13:55:36 UTC to 2024-10-10 13:59:10 UTC
```

## Tests

The tests cover parser formats and malformed lines, worker execution, sequential/parallel aggregation consistency, basic detector behavior, report serialization, and missing-file errors. Run with `ctest --test-dir build --output-on-failure`.

## Engineering notes

Batch-local aggregation reduces contention: workers do most parsing and counting without holding the shared mutex, then acquire it once per batch to merge. The bounded queue applies back-pressure to the reader. A condition variable wakes workers when tasks arrive and wakes producers when queue capacity becomes available. `wait()` checks both queued and active task counts under the same mutex.

The HTTP filters and detector rules are deliberately simple heuristics and do not prove malicious behavior. Requests-per-minute are based on UTC epoch minutes. In mixed-format input, application records count toward severity and IP counts while only access records contribute HTTP metrics.

## Future improvements

- Parse numeric Apache timezone offsets correctly and validate calendar dates strictly.
- Use sliding-window activity detection and configurable CLI thresholds.
- Make retention optional for bounded-memory million-line scans.
- Add external JSON parsing/validation and richer report ranking.
- Add cross-platform CI and collect benchmark numbers on documented hardware.

## Developer

Zainab Khawar — BS Information Technology, Bahria University Islamabad (2026).
