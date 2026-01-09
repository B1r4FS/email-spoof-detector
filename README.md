# email-spoof-detector
Python script for defensive analysis of .eml headers to detect internal domain spoofing

Python script for defensive analysis of `.eml` headers to detect internal domain spoofing attempts.

## What it does
This tool analyzes common email headers to flag suspicious messages impersonating internal senders:
- From vs Return-Path mismatch
- Authentication-Results inspection
  - SPF
  - DKIM
  - DMARC

## Requirements
- Python 3.9+

## Usage
```bash
python detect_spoof.py suspicious.eml iaudit.com.br

