# Secure MCP Server for Kali Linux 🛡️

A highly secure, enterprise-grade Model Context Protocol (MCP) server designed specifically for Kali Linux. This project bridges AI agents (via Termux/Android) to a secure local environment, enforcing strict authorization, modern cryptographic standards, and a zero-trust architecture.

## 🚀 Key Features

* **Strict Least-Privilege Execution:** Built-in safeguards against arbitrary code execution. Only explicitly allowlisted tools (e.g., specific network interface checks) are permitted. **No generic shell execution (`bash`, `exec`, etc.) is allowed.**
* **Robust Authentication (OAuth 2.0):** Implements dynamic client registration, authorization code flow with PKCE (S256), and secure token exchange.
* **Modern Cryptography:** Enforces ECDSA P-256 TLS for all communications with strict certificate pinning. 
* **Audit & Logging:** Comprehensive audit logs for all token exchanges, authorization requests, and tool executions. No credentials or bearer tokens are ever written to logs.
* **Network Isolation:** Designed to run entirely on a local network (LAN) behind UFW rules, ensuring the server is not exposed to the public internet.

## 🏗️ Architecture Overview

The system operates on a localized Android-to-Kali Linux pipeline:

```text
Android / Termux Client
      │
      │ LAN / Wi-Fi (TLS 1.3 Pinned)
      ▼
Kali Linux (Host: 0.0.0.0:8000)
      │
      ▼
Secure MCP Server (Python 3.14.6)
      │
      ├── Authentication & PKCE Validation
      ├── Authorization & Scope Checks
      ├── Audit Logging
      └── Allowlisted Read-Only Tools
