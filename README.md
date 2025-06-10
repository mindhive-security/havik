#  Havik

**Havik** is a modular CLI tool designed to scan and analyze security configurations in public cloud environments. It currently supports AWS, Azure and GCP. The tool helps identify weak spots such as missing encryption, overly permissive access, and insecure IAM policies — especially where native tools like AWS Security Hub fall short.

## ✨ Features

- 🔐 Encryption checks (S3/GCS buckets)
- 🌍 Public access detection
- 🔎 IAM policy analysis using LLMs (for AWS S3)
- 📊 Output in human-readable tables or JSON
- ⚙️ Modular structure, ready to scale across clouds and services

## 🚀 Installation

You can install locally using Python:

```bash
git clone https://github.com/mindhive-security/havik.git
cd havik
python -m pip install .
```

> **Note**: `pyproject.toml` and dependency management included. PyPI packaging is planned.

## ⚡ Quick Start

### AWS S3

```bash
havik aws s3 -e           # Encryption check
havik aws s3 -p           # Public access check and policy analysis
havik aws s3 -e -p --json # Combined check with JSON output
```

### GCP Storage

```bash
havik gcp storage -e -p   # Encryption + public access
```

### Azure Storage Account

```bash
havik az storage -e -p # Encryption + public access
```

### 🔍 AI-Assisted IAM Policy Evaluation (Optional)

This tool can evaluate bucket IAM policies using a local LLM (e.g., Mistral) for heuristic risk analysis. This feature is **optional** and currenty only works if:

1. You have a locally running LLM (tested with [Ollama](https://ollama.com/) and [Mistral](https://mistral.ai/)).
2. The `LLM_HOST` environment variable is set to point to your local LLM server (default: `http://localhost:11434`).

#### Example setup

```bash
ollama run mistral
export LLM_HOST=http://localhost:11434
```

## 🧠 Roadmap

- ✅ AWS S3: encryption, public access, IAM analysis
- ✅ GCP Storage: encryption, public access
- ✅ Azure Storage Account: encryption
- ⏳ Resource inventory module
- ⏳ Threat intelligence: toxic IAM combinations
- ⏳ Plugin support per cloud/service
- ⏳ Web interface or full SaaS version

## 🗂 Project Structure

```
src/havik/
├── aws/           # AWS-specific scanners
├── gcp/           # GCP-specific scanners
├── az             # Azure-specific scanners
├── cli.py         # CLI entry point
```

> Note: Output handling is currently mixed with logic — planned refactor will separate concerns.

## 📝 License

MIT — free to use, fork, and extend.

---

## ❤️ Contributing

This is an early-stage project. All contributions, issue reports, and suggestions are welcome!

---

## 🌍 Vision

Cloud Security Scanner aims to be a vendor-agnostic, open-source solution that complements native cloud security tooling — especially for European companies with strong compliance needs.

