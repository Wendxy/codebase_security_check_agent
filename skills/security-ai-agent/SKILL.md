---
name: security-ai-agent
description: Analyze an entire codebase with AI-driven security review across four perspectives: offensive exploitability, defensive control adequacy, data privacy handling, and operational realism. Use when users ask for full security analysis, structured findings, critical alerting, or deep dives by finding ID.
---

# Security AI Agent

Run repository scans with the CLI entrypoint:

```bash
security-agent scan .
```

Generate deep dives for specific finding numbers:

```bash
security-agent explain R-001 --run-id latest
```

List and inspect historical runs:

```bash
security-agent runs list
security-agent report show --run-id latest
```

When updating prompts or analysis behavior, load [references/prompts.md](references/prompts.md) first.

Default workflow:
1. Discover text files and exclude generated/binary paths.
2. Redact likely secrets before sending content to the model.
3. Execute offensive, defensive, and privacy passes.
4. Merge and deduplicate findings.
5. Run operational realism scoring.
6. Emit Markdown and JSON artifacts, and fail on Critical findings.
