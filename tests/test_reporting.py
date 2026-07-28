from pathlib import Path

from skillbom.manifest import build_manifest
from skillbom.reporting import to_sarif


def test_sarif_output(tmp_path: Path) -> None:
    skill = tmp_path / "empty"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: empty\ndescription: \"\"\n---\n", encoding="utf-8")
    sarif = to_sarif(build_manifest(skill))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
