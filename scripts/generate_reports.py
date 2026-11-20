#!/usr/bin/env python3
"""Local CLI utility to run the 5-Plane Google ADK assessment using explicit local workstation ADC."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.config import settings
from backend.report_generator import generate_all_executive_deliverables
from backend.session_vault import allow_local_cli_adc_context


def main() -> None:
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        print("Usage: .venv/bin/python scripts/generate_reports.py <GCP_SCOPE>")
        sys.exit(1)
    scope = sys.argv[1].strip()
    model_name = sys.argv[2] if len(sys.argv) > 2 else None
    out_dir = settings.export_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    with allow_local_cli_adc_context(export_dir=out_dir) as cli_sess:
        result = generate_all_executive_deliverables(scope=scope, model_name=model_name, force_refresh=True)
        for item in cli_sess.session_export_dir.iterdir():
            dest = out_dir / item.name
            if item.is_dir():
                shutil.rmtree(dest, ignore_errors=True)
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
