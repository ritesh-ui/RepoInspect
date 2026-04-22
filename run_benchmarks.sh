#!/bin/bash
set -e

echo "Starting Regression Benchmark..."

echo "1. Scanning OpenAI Agents SDK..."
python3 scan_repo.py https://github.com/openai/openai-agents-python --markdown reports/benchmarks/RESULTS_OPENAI_SDK.md

echo "2. Scanning Mem0..."
python3 scan_repo.py ./temp_mem0 --markdown reports/benchmarks/RESULTS_MEM0.md

echo "3. Scanning Firecrawl..."
python3 scan_repo.py ./temp_firecrawl --markdown reports/benchmarks/RESULTS_FIRECRAWL.md

echo "4. Scanning HF SmolAgents..."
python3 scan_repo.py https://github.com/huggingface/smolagents --markdown reports/benchmarks/RESULTS_SMOLAGENTS.md

echo "All scans completed successfully."
