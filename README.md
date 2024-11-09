# Time-Based Blind SQL Injection Scanner



This tool identifies time-based SQL injection vulnerabilities in a provided list of URLs.

## Requirements

- Python 3.7 or higher
- Modules specified in `requirements.txt`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your_username/time-sqli-scanner.git
   cd time-sqli-scanner
   pip install -r requirements.txt

Usage:
   ```bash
   python time_sqli_scanner.py -l urls.txt -p payloads.txt -o output.txt -c 10 -t 30 -d 5 -n 1 -m 20 -v
   ```
Parameters
-l, --list: File containing the list of URLs to scan (required)
-p, --payload: File with test payloads (required)
-o, --output: File to save vulnerable URLs (default: output.txt)
-c, --concurrency: Number of concurrent requests (default: 10)
-t, --timeout: Request timeout in seconds (default: 30)
-d, --delay: Response time in seconds suggesting vulnerability (default: 5.0)
-n, --min-response-time: Minimum response time considered vulnerable (default: 1.0)
-m, --max-response-time: Max response time before skipping the URL (default: 20)
-v, --verbose: Enable detailed output
--headers: Optional file in JSON format with custom headers
