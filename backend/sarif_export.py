"""
sarif_export.py — Converts security + dependency findings into SARIF 2.1.0,
the standard format GitHub (and most CI security tooling) consumes for code
scanning results. Upload the output via the github/codeql-action/upload-sarif
action to get findings inline on PRs and in the repo's Security tab.
"""

import os
import json

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# security finding severity -> SARIF result level
SECURITY_LEVEL_MAP = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
# dependency severity -> SARIF result level
DEPENDENCY_LEVEL_MAP = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _security_rule_id(f: dict) -> str:
    return f"codesage/{f.get('category', 'security')}"


def _security_results_and_rules(security_findings: list[dict]):
    rules, results, seen_rules = [], [], set()
    for f in security_findings:
        rule_id = _security_rule_id(f)
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": f.get("category", "security").replace("_", " ").title()},
                "defaultConfiguration": {"level": SECURITY_LEVEL_MAP.get(f["severity"], "warning")},
            })
        results.append({
            "ruleId": rule_id,
            "level": SECURITY_LEVEL_MAP.get(f["severity"], "warning"),
            "message": {"text": f["description"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file_path"].replace(os.sep, "/")},
                    "region": {"startLine": max(1, f.get("line_number", 1) or 1)},
                }
            }],
        })
    return results, rules


def _dependency_results_and_rules(dependency_findings: list[dict]):
    rules, results, seen_rules = [], [], set()
    for f in dependency_findings:
        rule_id = f"codesage/dependency/{f.get('vulnerability_id', 'unknown')}"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": f"{f['package_name']} — {f.get('vulnerability_id', '')}"},
                "defaultConfiguration": {"level": DEPENDENCY_LEVEL_MAP.get(f["severity"], "warning")},
            })
        manifest = "requirements.txt" if f.get("ecosystem") == "pypi" else "package.json"
        results.append({
            "ruleId": rule_id,
            "level": DEPENDENCY_LEVEL_MAP.get(f["severity"], "warning"),
            "message": {
                "text": f"{f['package_name']} {f['installed_version']}: {f['description']} "
                        f"(fix: upgrade to {f.get('fix_version', '?')})"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": manifest},
                    "region": {"startLine": 1},
                }
            }],
        })
    return results, rules


def build_sarif(security_findings: list[dict], dependency_findings: list[dict],
                 tool_version: str = "1.0.0") -> str:
    """Returns a SARIF 2.1.0 JSON document (as a string) combining security and
    dependency findings into a single run."""
    sec_results, sec_rules = _security_results_and_rules(security_findings)
    dep_results, dep_rules = _dependency_results_and_rules(dependency_findings)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CodeSage AI",
                    "informationUri": "https://github.com/",
                    "version": tool_version,
                    "rules": sec_rules + dep_rules,
                }
            },
            "results": sec_results + dep_results,
        }],
    }
    return json.dumps(sarif, indent=2)
