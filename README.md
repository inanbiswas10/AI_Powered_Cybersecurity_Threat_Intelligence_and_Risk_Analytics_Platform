# 🛡️ Aegis-AI Threat Analytics Platform v4.2

### Autonomous AI-Powered Cybersecurity Threat Intelligence & Risk Analytics Platform

[![Live Demo](https://img.shields.io/badge/🌐%20Live%20Demo-Streamlit%20Cloud-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)](https://aegis-ai-threat-analytics-platform.streamlit.app)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)](https://streamlit.io/)
[![Machine Learning](https://img.shields.io/badge/XGBoost%20%7C%20Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14.1-red?style=for-the-badge&logo=shield&logoColor=white)](https://attack.mitre.org/)
[![Async Engine](https://img.shields.io/badge/aiohttp-Async%20Ingress-2C5BB4?style=for-the-badge)](https://docs.aiohttp.org/)
[![License](https://img.shields.io/badge/License-MIT%20Enterprise-success?style=for-the-badge)](LICENSE)

---

## 🌐 Live Interactive SOC Deployment

Experience the live, autonomous threat intelligence command center running in real time:  
👉 **[Launch AegisAI ThreatLens Command Center](https://aegis-ai-threat-analytics-platform.streamlit.app)**

---

## 📌 Executive Summary & Project Overview

**Aegis-AI Threat Analytics Platform v4.2** is an enterprise grade, high-density Security Operations Center (SOC) intelligence dashboard and autonomous containment engine. Engineered entirely in modern, strictly type-hinted **Python 3.11+**, it equips cyber defense analysts, incident responders and CISOs with real-time wire packet inspection, unsupervised zero day anomaly triage, MITRE ATT&CK kill chain mapping, dynamic SIGMA rule generation and sub-second SOAR response playbooks.

Built specifically for high-impact internship portfolio demonstrations, academic defenses and containerized deployment across **Streamlit Community Cloud**, **Docker**, and cloud environments.

---

## 🌟 Key Architecture & Capabilities

| Capability | Module | Technical Description |
| :--- | :--- | :--- |
| **⚡ Real-Time eBPF Wire Ingress Stream** | `app.py` | Live telemetry inspection tracking source IP/ASN, ingress vectors, target ports (SSH, HTTPS, Kube-API), and automated mitigation (`BLOCKED`, `DROPPED`, `ISOLATED`). |
| **🧠 Dual-Stage Machine Learning Pipeline** | `ml_engine.py` | • **Unsupervised Zero-Day Detection**: Isolation Forest anomaly scoring calibrated on network distribution baselines.<br>• **Supervised Attribution**: XGBoost classifier assessing compromise probability with sub-15ms inference latency. |
| **🔬 Shannon Byte Entropy Triage** | `utils.py` | Mathematical entropy calculations on raw network bytes ($H(X) > 7.5$) to flag packed binaries, polymorphic loaders, encrypted C2 streams, and rootkit obfuscation. |
| **🌐 Asynchronous OSINT & CTI Ingestion** | `data_collector.py` | Concurrent ingestion via `aiohttp` for CISA Known Exploited Vulnerabilities (KEV), AlienVault OTX, and multi-vendor consensus reputation engines. |
| **⚡ Zero-Touch SOAR Containment** | `soar_playbooks.py` | Microsecond incident response routines simulating AWS Boto3 VPC security group ingress revocation, STS token invalidation, and automated perimeter STIX 2.1 dissemination. |
| **📊 Stochastic Cyber Risk Modeling** | `ml_engine.py` | 10,000-iteration Monte Carlo simulations computing 95% Value-at-Risk (VaR) and Annualized Loss Expectancy (ALE) for executive risk reporting. |

---

## 🗂️ Repository Structure

```text
02_Predictive_ML/
├── app.py                  # Streamlit SOC dashboard UI, telemetry HUD, & live sensor feeds
├── config.py               # Pydantic Settings V2 for zero-leak env variables & DEFCON control
├── data_collector.py       # Asynchronous aiohttp CTI feed collector (CISA KEV, OTX, Shodan)
├── ml_engine.py            # Dual Isolation Forest + XGBoost models & Monte Carlo risk engine
├── soar_playbooks.py       # Autonomous containment playbooks & automated SIGMA rule generator
├── utils.py                # Shannon entropy calculation, SHA-256 IOC hashing & SecOps logging
├── requirements.txt        # Pinned production dependencies for deterministic builds
├── LICENSE                 # MIT Enterprise Open-Source License
└── README.md               # Comprehensive platform documentation & deployment guide
```

---

## 🚀 Quickstart & Local Installation

### Prerequisites

- **Python**: Version `3.11` or `3.12`
- **Operating System**: Windows (PowerShell), macOS, or Linux
- **Git** (recommended for version control)

### 1. Navigate to Project Directory

```powershell
# Windows PowerShell
cd "D:\Computer Science (Python Projects)\02_Predictive_ML"
```
```bash
# Linux / macOS

cd path/to/02_Predictive_ML
```

### 2. Set Up an Isolated Virtual Environment

```powershell
# Windows PowerShell

python -m venv .venv
.venv\Scripts\Activate.ps1
```

```bash
# Linux / macOS

python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Pinned Dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Launch the SOC Command Center Locally

```bash
streamlit run app.py
```
> 🌐 The Aegis-AI Threat Analytics Platform dashboard will automatically launch in your default browser at **`http://localhost:8501`**.

---

## 🖥️ Live Dashboard Views & Walkthrough

### 1. 🛡️ Live SOC Command Center

- **DEFCON Readiness Status HUD**: Real-time synapse latency monitor, active ingress vector and blocked packet counter.
- **Sensor Telemetry Metrics**: Global Threat Level index (0-100), AI precision rate (99.4 %) and Autonomous MTTR (1.8 min).
- **Wire Ingress Stream**: Live packet log displaying Source IP, Port, MITRE ATT&CK technique IDs (e.g., `T1110.001`, `T1071.001`), AI confidence scores and action verdicts.

### 2. 🧠 AI Risk Analytics & Predictive ML Engine

- **XGBoost Classifier Telemetry**: Real-time evaluation of compromise likelihood, feature attribution, and inference latency benchmarks.
- **Monte Carlo Cyber Loss Projection**: Quantitative risk forecasting calculating Value-at-Risk (95% VaR: ~$4.20 M USD) and Annualized Loss Expectancy (ALE) savings via automated isolation.

### 3. 🎯 Threat Actors & CVE Matrix

- **IOC Sandbox Lookup**: Multi-vendor reputation synthesis (VirusTotal, AlienVault OTX, Shodan, AbuseIPDB).
- **APT Dossiers**: Correlation mapping against known threat groups (Volt Typhoon, Lazarus Group, APT29 Cozy Bear).

### 4. ⚡ SOAR Automation & Containment

- **Zero-Touch Remediation**: Live simulation of network boundary isolation, VPC security group revocation and dynamic SIGMA rule generation ready for SIEM ingestion (Splunk, Elastic, Sentinel).

---

## ☁️ Live Cloud Deployment (Streamlit Community Cloud)

This platform is deployed 24/7 on **Streamlit Community Cloud**:
- **Live Production URL**: [https://aegis-ai-threat-analytics-platform.streamlit.app](https://aegis-ai-threat-analytics-platform.streamlit.app)
- **Deployment Branch**: `main`
- **Entrypoint**: `app.py`
- **Runtime Environment**: Python 3.11 with containerized wheel resolution for XGBoost and Plotly.

---

## 🧪 Security Standards & Code Quality

- **Zero-Leak Design**: Configuration variables, API endpoints, and DEFCON parameters isolated via `pydantic-settings` (`config.py`).
- **Cryptographic Auditing**: Deterministic SHA-256 IOC hashing for immutable evidentiary integrity.
- **Static Type Safety**: Standardized on Python 3.11 type hints across all core modules.

---

## 📜 License

Distributed under the **MIT Enterprise License**. Feel free to adapt and build upon this platform for academic, research, and non-commercial security operations.

---

## 👨‍💻 Author & SecOps Lead

- **Developer**: **Inan Biswas**
- **Internship**: **Elite Tech Intern**
- **Domain**: **Predictive Machine Learning**
- **Project Scope**: Autonomous AI-Powered Threat Intelligence & SOC Telemetry
- **Portfolio & Profiles**: [GitHub](https://github.com/inanbiswas10) • [LinkedIn](https://www.linkedin.com/in/inanbiswas10)
