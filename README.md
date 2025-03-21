# Port Scanner

# Overview

This project is designed to perform network port scanning and service vulnerability detection using a web-based interface. It integrates a Flask backend and a React frontend, allowing users to input IP addresses, select scanning types, and receive detailed results, including service version detection and CVE information via Shodan API.

---

# Key Features

- **Port Scanning**: Supports TCP and UDP scanning across a wide range of ports.
- **Multiple Scanning Techniques**: Includes methods like TCP_FIN, NULL, XMAS, SYN, Connect, and ACK scans.
- **Service Version Detection**: Provides detailed service and OS version information.
- **CVE Integration**: Offers insights into known vulnerabilities via the Shodan API.
- **Logging**: Saves scanning results and service logs for easy review.

---

# Notes

**Accuracy Considerations**: Techniques like Stealth Scanning may yield inconsistent results depending on the target's configuration. The accuracy of the scan is not always guaranteed and should be interpreted cautiously.

**Legal Disclaimer**: Port scanning must be conducted in a lawful manner and should only target systems for which prior notification and authorization have been obtained. This tool is intended for educational and practical learning purposes, not for any illegal or malicious activities. We disclaim any responsibility for the consequences of misuse or irresponsible actions by users who disregard this warning.

---

# Guide for Operation

***Please choose and proceed with one of the two preferred methods: Option 1 or Option 2.***

## 1. Docker-compose.yml

```bash
docker-compose up # for Windows
docker compose up # for MacOS
```

## 2-1. Front End

1. Navigate to the `frontend` directory:

```bash
cd frontend
```

2. Install required packages:

```bash
npm install
```

3. Start the React development server:

```bash
npm start
```

4. Access the application via `http://localhost:3000`

## 2-2. Back End

1. Navigate to the `backend` directory:

```bash
cd backend
```

2. Install dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

3. Start the Flask server:

```bash
python run.py
```

4. The server runs at `http://localhost:5001`
 
***Ensure both frontend and backend servers are running for full functionality.***

---

# Tech. Stack Info

## Front End

> React / Material UI

## Back End

> Flask / Python

## Miscellaneous

> Shodan API / Docker

---
