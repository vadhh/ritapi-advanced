"""Verify all Prometheus metric names referenced in alerts.yaml are registered."""
import re
from pathlib import Path

import yaml


def _get_registered_metric_names():
    """Import metrics module and return all registered base metric names."""
    # Import metrics to trigger registration
    import prometheus_client

    import app.utils.metrics  # noqa: F401
    return set(prometheus_client.REGISTRY._names_to_collectors.keys())


def test_alert_metric_names_exist():
    """Every ritapi_* metric in alerts.yaml must be registered in metrics.py."""
    alerts_path = Path("docker/prometheus/alerts.yaml")
    content = alerts_path.read_text()
    data = yaml.safe_load(content)

    registered = _get_registered_metric_names()

    missing = []
    for group in data.get("groups", []):
        for rule in group.get("rules", []):
            expr = rule.get("expr", "")
            alert_name = rule.get("alert", "unknown")
            # Find all ritapi_* metric references
            refs = re.findall(r"ritapi_\w+", expr)
            for ref in refs:
                # Strip Prometheus suffixes to get base metric name
                base = re.sub(r"_(total|bucket|count|sum|created)$", "", ref)
                if base not in registered and ref not in registered:
                    missing.append(f"Alert '{alert_name}': '{ref}' not registered (base: '{base}')")

    assert not missing, "Broken metric references in alerts.yaml:\n" + "\n".join(missing)
