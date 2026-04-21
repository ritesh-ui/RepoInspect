# 🛡️ RepoInspect: Deterministic AI Security Engine

**The next generation of AppSec.** RepoGuard is a high-performance security engine that eliminates the "False Positive tax" by merging the surgical precision of **Abstract Syntax Trees (AST)** with the deep reasoning of **Autonomous AI Agents**.

[![RepoGuard Security Scan](https://github.com/ritesh-ui/RepoGuard/actions/workflows/repoguard.yml/badge.svg)](https://github.com/ritesh-ui/RepoGuard/actions/workflows/repoguard.yml)
[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![Performance](https://img.shields.io/badge/Parallel-Scale-green.svg)](#)

---

## ⚡ The Deterministic Moat

Legacy SAST tools generate noise. Naive AI scanners are slow and hallucinate. **RepoGuard wins by being Hybrid.**

1.  **Phase 1: Deterministic Filter (The Scalpel)**
    Our custom Two-Pass engine scans thousands of files in parallel. It doesn't just look for strings; it maps Abstract Syntax Trees to identify structurally valid vulnerability paths.
2.  **Phase 2: Agentic Forensics (The Brain)**
    Instead of flagging every "hotspot," RepoGuard launches an **Autonomous Security Agent**. If a finding is ambiguous, the Agent uses dynamic tools (`read_file`, `text_search`) to contextually trace variable origins across file boundaries before rendering a verdict.

---

## 🚀 Key Features

### 🔍 Precision Audit Engine
- **Inter-Procedural Taint Tracking**: A two-pass architecture that builds a global function propagation map. We track user-controlled data even when it's passed through multiple helper functions.
- **Flow-Sensitive Analysis**: Understands variable overrides. If a tainted variable is reassigned to a safe literal, RepoGuard dynamically clears the risk.
- **Word-Boundary Intelligence**: Semantic segment-splitting prevents false positives on names like `metadata` or `target`.

### 🛡️ Enterprise Language Support
Deep AST and Tree-Sitter support for:
- **Python** (Native ast.NodeVisitor)
- **JavaScript / TypeScript** (Tree-Sitter)
- **Java** (Tree-Sitter)
- **Go** (Tree-Sitter)

### 🤖 AI-Native Security (LLM Security)
Specialized detection for vulnerabilities standard scanners miss:
- **Prompt Injection**: LLM01:2023 tracing.
- **Insecure Tool/Agent Usage**: LLM08:2023 Excessive Agency.
- **Sensitive Information Disclosure in Prompts**: LLM06:2023.

---

## 🏗 High-Level Architecture

```mermaid
graph TD
    CLI[scan_repo.py] --> P1[Pass 1: Global Prop Map Builder]
    P1 -->|Parallel Processes| Map[Inter-Procedural Taint Map]
    Map --> P2[Pass 2: Deep Pattern Scanner]
    P2 -->|Hotspots| Agent[Autonomous Forensic Agent]
    Agent -->|Tool Use: read_file| Root[Variable Root Tracing]
    Agent -->|Tool Use: text_search| Cross[Cross-File Validation]
    Root --> Logic[Deterministic Logic Check]
    Logic --> Result[Verified Vulnerability]
    Result --> Report[MD/JSON/CLI Reports]
```

---

## 🛠 Installation & Setup

1. **Clone and Enter**:
   ```bash
   git clone https://github.com/ritesh-ui/RepoGuard.git && cd RepoGuard
   ```

2. **Environment Setup**:
   ```bash
   python3 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   pip install tree-sitter tree-sitter-languages
   ```

3. **Configure API**:
   Create a `.env` file:
   ```env
   OPENAI_API_KEY=your_key_here
   OPENAI_MODEL=gpt-4o-mini
   ```

---

## 📖 Usage

### Standard Scan
```bash
python3 scan_repo.py /path/to/repo
```

### Enterprise CI/CD Scan (Fail on High/Critical)
```bash
python3 scan_repo.py . --fail-on High --markdown SECURITY_REPORT.md
```

### Remote Repository Audit
```bash
python3 scan_repo.py https://github.com/org/repo --branch main
```

---

## 🏆 Case Studies: Real-World Impacts

| Project | Findings | Status | Report |
| :--- | :--- | :--- | :--- |
| **HF SmolAgents** | 0 High Risks (Verified Safe) | ✅ Audited | [View Report](reports/benchmarks/RESULTS_SMOLAGENTS.md) |
| **OpenAI Agents SDK** | 1 Critical, 4 High Risks | ✅ Audited | [View Report](reports/benchmarks/RESULTS_OPENAI_SDK.md) |

> [!IMPORTANT]
> **Case Study: Agentic Reasoning**
> In a recent audit of the OpenAI Agents SDK, RepoGuard successfully traced a `subprocess.check_call` vulnerability by identifying that a "safe-looking" package list was actually sourced from external user intent across three nested function calls—a flow that every other modern scanner missed.

---

## 🛡️ License
Distributed under the MIT License. See `LICENSE` for more information.
