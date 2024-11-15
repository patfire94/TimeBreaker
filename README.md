# Time-Based Blind SQL Injection Scanner

![Scanner Banner](https://github.com/user-attachments/assets/dd9e438b-8c6d-4e67-8661-688fa5798aae)



This tool identifies time-based SQL injection vulnerabilities in a provided list of URLs. Is intended for testing large lists of urls for masshunting.

## Requirements

- Python 3.7 or higher
- Modules specified in `requirements.txt`

## Installation

Clone the repository:
   ```bash
   git clone https://github.com/your_username/TimeBreaker.git
   cd TimeBreaker
   pip install -r requirements.txt
   ``` 
## Usasge

Usage:
   ```bash
   python3 timebreaker.py -h
   python3 timebreaker.py -l urls.txt -p payloads.txt -o output.txt -c 10 -t 30 -d 5 -n 1 -m 20 -v
   python3 timebreaker.py -l urls.txt -p payloads.txt --webhook "https://discord.com/api/webhooks/your-webhook-id/your-webhook-token"
   ```
## Discord webhook Integration:

![Discord_webhook](https://github.com/user-attachments/assets/a5c0023b-b8e8-47c1-9369-ccb00a2f3250)


## Parameters

| Parameter                | Description                                                                      |
|--------------------------|----------------------------------------------------------------------------------|
| `-l`, `--list`           | File containing the list of URLs to scan (required)                              |
| `-p`, `--payload`        | File with test payloads (required)                                               |
| `-o`, `--output`         | File to save vulnerable URLs (default: `output.txt`)                             |
| `-c`, `--concurrency`    | Number of concurrent requests (default: `10`)                                    |
| `-t`, `--timeout`        | Request timeout in seconds (default: `30`)                                       |
| `-d`, `--delay`          | Response time in seconds suggesting vulnerability (default: `5.0`)               |
| `-n`, `--min-response-time` | Minimum response time considered vulnerable (default: `1.0`)                  |
| `-m`, `--max-response-time` | Max response time before skipping the URL (default: `20`)                     |
| `-v`, `--verbose`        | Enable detailed output                                                           |
| `--headers`              | Optional file in JSON format with custom headers                                 |
| `--webhook`              | Discord webhook URL for sending alerts                                           |
