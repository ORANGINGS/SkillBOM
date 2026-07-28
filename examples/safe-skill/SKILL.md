---
name: safe-skill
description: Summarizes a local Markdown document. Use when the user asks for a concise summary of a local .md file.
license: MIT
compatibility: Requires Python 3.11 or newer. No network access.
metadata:
  version: "0.1.0"
---

# Local Markdown summarizer

## Workflow

1. Confirm that the input is a local Markdown file.
2. Run `scripts/summarize.py INPUT.md`.
3. Return the generated summary and mention any unreadable sections.

## Constraints

- Do not make network requests.
- Do not modify the source document.
- Only write to the output path selected by the user.
