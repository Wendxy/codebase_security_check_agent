# Prompt Contracts

## Comprehension Pass

Goal: produce grounded file/chunk summaries focused on security-relevant behavior.

Output JSON:
```json
{
  "summary": "...",
  "suspicious_points": ["..."]
}
```

## Lens Passes

Run separately for:
- `offensive`
- `defensive`
- `privacy`

Output JSON:
```json
{
  "findings": [
    {
      "title": "...",
      "severity": "critical|high|medium|low|info",
      "perspectives": ["offensive|defensive|privacy"],
      "description": "...",
      "attack_or_failure_scenario": "...",
      "recommendation": "...",
      "evidence": [
        {
          "file": "path",
          "start_line": 1,
          "end_line": 1,
          "snippet_redacted": "..."
        }
      ],
      "confidence": 0.0
    }
  ]
}
```

## Operational Realism Pass

Goal: identify practical control guidance vs security theater.

Output JSON:
```json
{
  "entries": [
    {
      "title": "...",
      "practicality_score": 0,
      "theater_flag": false,
      "notes": "..."
    }
  ]
}
```

## Guardrails

1. Require concrete evidence in files and lines.
2. Prefer actionable remediations over abstract advice.
3. Keep privacy findings focused on data lifecycle and exposure paths.
4. Mark Critical only for exploit-ready or major confidentiality/integrity impact issues.
