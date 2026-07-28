from skillbom.diffing import compare_manifests


def test_capability_drift_is_high() -> None:
    old = {
        "skills": [
            {"name": "demo", "capabilities": [], "dependencies": [], "findings": [], "digest": "a"}
        ]
    }
    new = {
        "skills": [
            {
                "name": "demo",
                "capabilities": [{"name": "network-access"}],
                "dependencies": [],
                "findings": [],
                "digest": "b",
            }
        ]
    }
    drifts = compare_manifests(old, new)
    capability = next(item for item in drifts if item.kind == "capability-added")
    assert capability.item == "network-access"
    assert capability.severity.value == "high"
