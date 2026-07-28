from __future__ import annotations

import argparse
from pathlib import Path


def summarize(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    paragraphs = [part.strip() for part in text.split("\n\n") if part.strip()]
    return "\n\n".join(paragraphs[:3])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    print(summarize(args.input))


if __name__ == "__main__":
    main()
