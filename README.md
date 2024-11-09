# Time-Based Blind SQL Injection Scanner

![Scanner Banner](![2024-11-09 21_29_10-](https://github.com/user-attachments/assets/520a9570-cd12-4638-a4be-0603ab7c50da))



This tool identifies time-based SQL injection vulnerabilities in a provided list of URLs.

## Requirements

- Python 3.7 or higher
- Modules specified in `requirements.txt`

## Installation

Clone the repository:
   ```bash
   git clone https://github.com/your_username/time-sqli-scanner.git
   cd time-sqli-scanner
   pip install -r requirements.txt
   ``` 
## Usasge

Usage:
   ```bash
   python3 timebreaker.py -h
   python3 timebreaker.py -l urls.txt -p payloads.txt -o output.txt -c 10 -t 30 -d 5 -n 1 -m 20 -v
   ```

