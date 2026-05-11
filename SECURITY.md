# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | ✅        |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
responsibly using **GitHub's private vulnerability reporting**:

1. Go to the [Security Advisories](https://github.com/detection-forge/agentic-detection-lookups/security/advisories) page.
2. Click **"Report a vulnerability"**.
3. Provide a clear description of the issue, steps to reproduce, and any
   potential impact.

**Please do not open a public issue for security vulnerabilities.**

## Scope

This project distributes **static CSV lookup files** and an **MCP server**
that reads them. Security concerns may include:

- **Data integrity** — tampered or malicious entries in lookup CSVs
- **Supply chain** — compromised upstream data sources (LOLBAS, GTFOBins)
- **MCP server** — input validation, path traversal, or injection in tool handlers
- **Dependencies** — vulnerabilities in Python package dependencies

## Response

We aim to acknowledge reports within **48 hours** and provide a fix or
mitigation plan within **7 days** for confirmed vulnerabilities.
