# Phishing IOC Enrichment Report

**Source file:** `A Black Friday ​Opportunity for You!.eml`  
**Generated:** 2026-07-10 22:15:55

## Email Metadata

- **From:** Joy of the Trade <editorial@doctricant.com>
- **Return-Path:** 
- **Subject:** A Black Friday ​Opportunity for You!
- **Date:** Fri, 10 Jul 2026 23:18:53 +0000
- **SCL:** -1
- **Authentication-Results:** N/A

## Extracted IOCs

- **Sender domain:** doctricant.com
- **IPs (from Received headers):** none found
- **URLs in body:** 1 found
  - https://www.prizegives.com/can/cbcd8e75-b3ac-4fbb-bf4c-e603a89cbb3d/948fce19-cbac-4531-8793-1d76308212b7/0be2a8c7-2531-4f8d-a150-6c2010cd8f1e/login?id=V3RIL3ZiOWZBTjNGWkkxRGlhbVZTd0djbDJQZjJNaVlYODVjWFQvOUY0L01ZaVlIWFVLR1M4Z1RlYVZoYjVtOHBDYnIzM055ZGkxdWpmbm84eTNaVUtocS93Sm0yTS9jU1Bxa0todnQwODlEcjNvK2t0d0ZkUjdUNkV5ZldCVHY2N0lLbW1IcXI5MzZIcmh1N013Vnpud1dCV0k4WVZtd1ZUdk0vSW5sVStVVXZFVG5Cb3JwSE02MFd1UFB2QWFYaDVhVXdDUjRwSWl1VitUZjhReWd1L0ZsY1g5R1VsZFhTRjlmdDl3V0RCZHFKdlRwVmo1YklUTDRRZmljdFVONWFqdndkcjdEN3oweTczZDJMNTI5YzByZzhKZG9yYkpYVEFnbE1NS2pVWE5keDAwUU43bU1oTzNyck1WWlVlQW5HQkpVbWNrYmd2dThnay80LzMxUE44VTNoNDVMSjd1Q2pUU0Uvd3ZJbkxaTGpRQVAzb2s1eUl6ejMrVmowd0ZSdFIwVWpmV1lKOUdRVUVqR0JPZ3hqTUVJVXpEaHE5NHZUUE5MQmZ0UkFiN1dqazhHY2pGck52UVd5WVoxd0YyUQ

## Enrichment Results

### Sender domain: doctricant.com
```
{'malicious': 7, 'suspicious': 1, 'undetected': 31, 'harmless': 52, 'timeout': 0}
```

### URL: https://www.prizegives.com/can/cbcd8e75-b3ac-4fbb-bf4c-e603a89cbb3d/948fce19-cbac-4531-8793-1d76308212b7/0be2a8c7-2531-4f8d-a150-6c2010cd8f1e/login?id=V3RIL3ZiOWZBTjNGWkkxRGlhbVZTd0djbDJQZjJNaVlYODVjWFQvOUY0L01ZaVlIWFVLR1M4Z1RlYVZoYjVtOHBDYnIzM055ZGkxdWpmbm84eTNaVUtocS93Sm0yTS9jU1Bxa0todnQwODlEcjNvK2t0d0ZkUjdUNkV5ZldCVHY2N0lLbW1IcXI5MzZIcmh1N013Vnpud1dCV0k4WVZtd1ZUdk0vSW5sVStVVXZFVG5Cb3JwSE02MFd1UFB2QWFYaDVhVXdDUjRwSWl1VitUZjhReWd1L0ZsY1g5R1VsZFhTRjlmdDl3V0RCZHFKdlRwVmo1YklUTDRRZmljdFVONWFqdndkcjdEN3oweTczZDJMNTI5YzByZzhKZG9yYkpYVEFnbE1NS2pVWE5keDAwUU43bU1oTzNyck1WWlVlQW5HQkpVbWNrYmd2dThnay80LzMxUE44VTNoNDVMSjd1Q2pUU0Uvd3ZJbkxaTGpRQVAzb2s1eUl6ejMrVmowd0ZSdFIwVWpmV1lKOUdRVUVqR0JPZ3hqTUVJVXpEaHE5NHZUUE5MQmZ0UkFiN1dqazhHY2pGck52UVd5WVoxd0YyUQ
```
{'note': 'URL submitted for first-time analysis — re-run script in ~60s for results'}
```

## Risk Score

**Score: 75/100 — HIGH — Escalate immediately**

### Contributing factors:
- SCL=-1 (spam filtering bypassed — typical of simulation platforms AND of attacker-controlled trusted relays; not conclusive alone)
- Sender domain: 7 VT vendors flagged malicious
- Sender domain: 1 VT vendors flagged suspicious

## Analyst Notes

_(Add manual observations here — lure theme, plausibility, why a real user might click, recommended action: block sender/domain, notify affected users, submit for takedown, etc.)_
