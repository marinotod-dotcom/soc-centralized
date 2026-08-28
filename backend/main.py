import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv

from src.utils.cli_utils import parse_args
from src.utils.wazuh_utils import build_clients
from src.pipelines import (
    run_kpi_report_pipeline,
    run_action_plan_pipeline,
    run_coverage_pipeline,
)

sys.stdout.reconfigure(encoding="utf-8")
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


def main() -> None:
    date_from, date_to, pretty_print, only, older_than, reference_fleet = parse_args()

    indexer, manager = build_clients()

    all_pipelines = {
        "kpi_report": lambda: run_kpi_report_pipeline(
            date_from, date_to, pretty_print, indexer, manager, BASE_DIR
        ),
        "action_plan": lambda: run_action_plan_pipeline(
            date_from, date_to, indexer, BASE_DIR
        ),
        "coverage": lambda: run_coverage_pipeline(
            date_to, manager, BASE_DIR, older_than=older_than, reference_fleet=reference_fleet
        ),
    }

    pipelines = (
        all_pipelines
        if only == "all"
        else {only: all_pipelines[only]}
    )

    with ThreadPoolExecutor(max_workers=len(pipelines)) as executor:
        futures = {executor.submit(fn): name for name, fn in pipelines.items()}

        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                print(f"[{name}] terminé avec succès : {result}")
            except Exception as exc:
                print(f"[{name}] a échoué : {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()