# security-ai-agent

This is an AI-powered codebase security analyser that reads your repo with an LLM and produces structured security findings from four perspectives:

1. Offensive: what an attacker can exploit
2. Defensive: whether controls are adequate
3. Data Privacy: whether sensitive data is handled safely
4. Operational Realism: whether recommendations are practical or not

## What This Project Does

`security-ai-agent` scans the entire codebase (text files), redacts likely secrets before prompt submission, runs AI analysis passes, deduplicates overlaps, and produces findings which include:

- Numbered findings (`R-001`, `R-002`, ...)
- Severity-ranked report (`critical`, `high`, `medium`, `low`, `info`)
- Evidence with file and line references
- Deep-dive retrieval by finding ID
- Immediate critical alert artifact for critical findings

## Core Commands

- `security-agent scan [TARGET_PATH]`
- `security-agent explain <FINDING_ID> [--run-id latest]`
- `security-agent runs list`
- `security-agent report show [--run-id latest]`

## Requirements

- Python `3.11+`
- OpenAI API key (`OPENAI_API_KEY`)

## Installation

From project root:

```bash
# Create and activate virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install package in editable mode
pip install -U pip setuptools wheel
pip install -e .
```

Verify install:

```bash
security-agent --help
```

## Configuration

Set your OpenAI key:

```bash
export OPENAI_API_KEY="sk-...your-key..."
```

## How to Run

### 1) Full scan

```bash
security-agent scan .
```

### 2) Smaller and Faster scoped scan (recommended for first run)

```bash
security-agent scan . \
  --model gpt-4.1-mini \
  --max-files 20 \
  --include '*.py' \
  --include '*.js' \
  --exclude 'tests/**' \
  --exclude 'docs/**'
```

### 3) View latest report

```bash
security-agent report show --run-id latest
```

### 4) Deep dive on one finding

```bash
security-agent explain R-001 --run-id latest
```

### 5) List previous runs

```bash
security-agent runs list
```

## Scan Options

`scan` supports:

- `--model` (default: `gpt-5`)
- `--max-files` (default: unlimited)
- `--include` (repeatable glob filter)
- `--exclude` (repeatable glob filter)
- `--output-dir` (default: `.security-agent/runs`)
- `--top-findings` (default: `25`)
- `--fail-on` (default and only supported policy: `critical`)
- `--format` (comma-separated `md,json`, default both)

## Output Artifacts

Each run creates:

`/Users/giang/security_check_agent/.security-agent/runs/<run-id>/`

- `security-report.md` (human-readable report)
- `findings.json` (machine-readable findings)
- `metadata.json` (run metadata)
- `critical_alert.json` (present when at least one Critical finding exists)

## Exit Codes

- `0`: completed without Critical findings
- `2`: completed with at least one Critical finding
- `1`: runtime/configuration error

## Progress and Timing Visibility

During scan, console logs include:

- Chunk/batch progress for each AI pass
- Per-step timing
- Total runtime in final JSON summary