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

2. Usage:
   ```bash
   python3 timebreaker.py -h
   python3 timebreaker.py -l urls.txt -p payloads.txt -o output.txt -c 10 -t 30 -d 5 -n 1 -m 20 -v
   ```

