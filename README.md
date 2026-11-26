# sec-learning-lab

A 7-day Python security practice log, written while studying Information Security Technology in my first year.

Each day has 3 short sessions (morning, noon, evening), so there are 21 small exercises in total. Each one is a single `solution.py` (roughly 60-120 lines, mostly standard library) with a `test_solution.py` that checks it using `pytest`. The goal is to practise reading, writing and testing small security-related scripts, not to build production tools.

These are learning exercises. They may be simplified, and they should only be pointed at systems you own or have permission to test.

## Layout

```
dayNN/<slot>_<topic>/
    solution.py        # the exercise
    test_solution.py   # pytest tests
curriculum.json        # the list of exercises and their status
run_session.ps1        # runs the next pending exercise
```

## Running an exercise

```
pip install pytest ruff
ruff check day01/morning_subnet_calculator
pytest day01/morning_subnet_calculator
```

## Progress

| # | Day | Slot | Folder | Exercise | Status |
|---|-----|------|--------|----------|--------|
| 1 | 1 | Morning | `day01/morning_subnet_calculator` | IPv4 Subnet & CIDR Calculator | Completed |
| 2 | 1 | Noon | `day01/noon_password_entropy` | Password Strength & Entropy Checker | Completed |
| 3 | 1 | Evening | `day01/evening_http_headers` | HTTP Security Header Inspector | Completed |
| 4 | 2 | Morning | `day02/morning_port_checker` | Single-Host TCP Port & Banner Checker | Completed |
| 5 | 2 | Noon | `day02/noon_hash_verifier` | SHA-256 File Integrity Verifier | Completed |
| 6 | 2 | Evening | `day02/evening_cipher_lab` | Caesar & XOR Cipher Lab | Pending |
| 7 | 3 | Morning | `day03/morning_ssh_log_counter` | SSH Auth Log Failed-Login Counter | Pending |
| 8 | 3 | Noon | `day03/noon_url_parser` | URL & Query Parameter Inspector | Pending |
| 9 | 3 | Evening | `day03/evening_dns_lookup` | DNS Record Lookup Tool | Pending |
| 10 | 4 | Morning | `day04/morning_permission_auditor` | Linux File Permission & SUID Auditor | Pending |
| 11 | 4 | Noon | `day04/noon_codec_cli` | Base64/Hex/URL Encoder-Decoder CLI | Pending |
| 12 | 4 | Evening | `day04/evening_tls_expiry` | TLS Certificate Expiry Checker | Pending |
| 13 | 5 | Morning | `day05/morning_ipv4_unpacker` | Raw IPv4 Header Bitwise Unpacker | Pending |
| 14 | 5 | Noon | `day05/noon_config_scanner` | Config & .env Keyword Scanner | Pending |
| 15 | 5 | Evening | `day05/evening_cookie_auditor` | HTTP Cookie Security Flag Checker | Pending |
| 16 | 6 | Morning | `day06/morning_mac_lookup` | MAC Address & Vendor Prefix Lookup | Pending |
| 17 | 6 | Noon | `day06/noon_dir_scanner_sim` | Local Directory Wordlist Simulator | Pending |
| 18 | 6 | Evening | `day06/evening_json_log_filter` | JSON Log Filter & Anomaly Counter | Pending |
| 19 | 7 | Morning | `day07/morning_whois_parser` | WHOIS & Domain Age Parser | Pending |
| 20 | 7 | Noon | `day07/noon_sqli_xss_detector` | Basic SQLi & XSS Pattern Detector | Pending |
| 21 | 7 | Evening | `day07/evening_week1_toolkit` | Week-1 Mini Security Toolkit Menu | Pending |
