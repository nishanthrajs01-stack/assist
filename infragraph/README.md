# 🌐 InfraGraph — Multi-Source Attack Surface Graph & Orphan Asset Tracker

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-teal.svg)]()
[![Cytoscape.js](https://img.shields.io/badge/Visualizer-Cytoscape.js-orange.svg)]()

**InfraGraph** is a high-speed intelligence engine and heterogeneous knowledge graph built for security researchers and bug bounty hunters. It transforms messy, multi-cloud target infrastructure into an actionable, relational attack surface graph and automatically hunts for high-severity vulnerabilities like **Dangling DNS / Subdomain Takeovers**, **Orphan Cloud Assets**, and **Shadow IT Exposure**.

---

## ⚡ Key Features

1. **Heterogeneous Attack Surface Graph**:
   * Models the target ecosystem as a directed knowledge graph (`Domain` ➔ `Subdomain` ➔ `CNAME` ➔ `Cloud Resource` ➔ `IP Address` ➔ `BGP Prefix / ASN Carrier`).
   * Supports exporting to Cytoscape.js JSON, NetworkX DiGraph, and Graphviz DOT formats.

2. **Subdomain Takeover & Dangling Pointer Engine**:
   * Fingerprints **25+ major cloud providers & SaaS platforms** (AWS S3, Elastic Beanstalk, CloudFront, Azure App Services, Traffic Manager, GCP Storage, GitHub Pages, Heroku, Fastly, Shopify, Netlify, Surge.sh, Zendesk, Pantheon, etc.).
   * Detects claimable buckets, deleted apps, and unlinked CNAME targets with active HTTP signature and NXDOMAIN verification.

3. **High-Throughput Asynchronous Recon**:
   * Concurrent DNS query engine for `A`, `AAAA`, `CNAME`, `NS`, `MX`, and `TXT` records.
   * Certificate Transparency (CT log) parsing via crt.sh.
   * Built-in wordlist permutator for high-value target subdomains (`api`, `dev`, `staging`, `auth`, `admin`, `vpn`, `k8s`, `vault`).

4. **IP-to-ASN & Carrier Enrichment**:
   * Automatically resolves IP blocks to origin ASNs and BGP routing CIDRs via Team Cymru DNS.

5. **Snapshot Differential Analysis (`T0` vs `T1`)**:
   * Compares infrastructure states over time.
   * Instantly highlights **newly deployed subdomains**, **decommissioned servers**, and **newly introduced takeover risks**.

6. **Interactive Cytoscape Visualizer & Web Dashboard**:
   * Real-time dark-themed graph interface with force-directed (`CoSE`), hierarchical (`Breadthfirst`), and concentric layouts.
   * Interactive Inspector Drawer displaying asset telemetry, CNAME chains, and step-by-step remediation advice.

---

## 🚀 Quickstart

### 1. Installation

```bash
# Clone the repository and navigate into the directory
cd /home/user/infragraph

# Activate the virtual environment
source venv/bin/activate

# Install the package in development mode
pip install -e .
```

---

## 🛠️ CLI Usage

### A. Run an Attack Surface Scan

```bash
infragraph scan target.com --output target_t0.json
```

* Flags:
  * `-o, --output <file>`: Save graph snapshot to a JSON file.
  * `-c, --concurrency <int>`: Concurrency level for async DNS resolution (default: 50).
  * `--no-bruteforce`: Skip common prefix permutation and rely only on CT logs.

### B. Differential Snapshot Diffing (`infragraph diff`)

Track infrastructure changes and catch newly introduced takeovers minutes after deployment:

```bash
infragraph diff target_t0.json target_t1.json
```

### C. Launch the Interactive Web Dashboard & API

```bash
infragraph serve --port 8888
```

Open your browser at `http://localhost:8888` to explore the interactive visual graph, filter by risk level, and run new target scans.

---

## 🏗️ Architecture

```
infragraph/
├── models/
│   ├── nodes.py         # Domain, Subdomain, IP, ASN, CloudResource models
│   ├── edges.py         # Graph relationship definitions (OWNS, RESOLVES_TO, DANGLING_TARGET)
│   └── graph.py         # InfraGraph core graph container & serializers
├── recon/
│   ├── dns_resolver.py  # Async DNS query engine
│   ├── ct_logs.py       # Certificate Transparency log fetcher
│   ├── asn_lookup.py    # IP-to-ASN/CIDR resolution
│   └── wordlist.py      # High-value subdomain candidate generator
├── analyzer/
│   ├── signatures.py    # Cloud provider takeover signatures
│   ├── dangling.py      # Dangling CNAME & takeover verification
│   ├── diff.py          # Differential snapshot comparator (T0 vs T1)
│   └── anomalies.py     # Attack surface anomaly detector
├── web/
│   ├── server.py        # FastAPI REST API
│   ├── sample_data.py   # Multi-cloud target demo data
│   └── static/
│       ├── index.html   # Cytoscape.js graph dashboard
│       ├── app.js       # Frontend controller & inspector drawer
│       └── style.css    # Modern dark theme
└── cli.py               # Click command-line interface
```

---

## 🛡️ License
MIT License. Built for ethical security research and authorized bug bounty hunting.
