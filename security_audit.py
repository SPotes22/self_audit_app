import os
import re

EXCLUDED_DIRS = {"venv", "__pycache__", ".git", "site-packages"}

VULN_PATTERNS = {
    "pickle_usage": r"pickle\.load",
    "weak_sanitization": r"\.replace\(",
    "debug_prints": r"\bprint\(",
    "hardcoded_path": r"models/",
}


def should_skip(path: str) -> bool:
    return any(excluded in path.split(os.sep) for excluded in EXCLUDED_DIRS)


def scan_file(filepath):
    findings = []

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

        for vuln_name, pattern in VULN_PATTERNS.items():
            if re.search(pattern, content):
                findings.append(vuln_name)

    return findings


def scan_project(root="."):
    report = {}

    for root_dir, _, files in os.walk(root):
        if should_skip(root_dir):
            continue

        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root_dir, file)

                if should_skip(path):
                    continue

                issues = scan_file(path)
                if issues:
                    report[path] = issues

    return report


if __name__ == "__main__":
    print("=== MINI SAST INTERNO ===")
    print("Scope: Código propietario únicamente")

    results = scan_project()

    if results:
        print("⚠️ Posibles vulnerabilidades detectadas:\n")
        for file, issues in results.items():
            print(f"{file}:")
            for issue in issues:
                print(f"  - {issue}")
    else:
        print("✓ No se detectaron patrones inseguros básicos.")
