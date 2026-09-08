import sys
from pathlib import Path
from src.pipelines import (
    run_kpi_report_pipeline,
    run_action_plan_pipeline,
    run_daily_action_plan_pipeline,
    run_coverage_pipeline,
)
from dotenv import load_dotenv
from src.utils.cli_utils import parse_args
from src.utils.wazuh_utils import build_clients
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.decorador.resilicence_decorador import failure_registry
from src.routes.daily_action_plan_routes import router as daily_action_plan_router

app.include_router(auth_router)
app.include_router(daily_action_plan_router)

sys.stdout.reconfigure(encoding="utf-8")
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


def main() -> None:
    parsed = parse_args()

    indexer, manager = build_clients()

    all_pipelines = {
        "kpi_report": lambda: run_kpi_report_pipeline(
            parsed.date_from, parsed.date_to, parsed.pretty, indexer, manager, BASE_DIR
        ),
        "action_plan": lambda: run_action_plan_pipeline(
            parsed.date_from, parsed.date_to, indexer, BASE_DIR
        ),
        "daily_action_plan": lambda: run_daily_action_plan_pipeline(
            indexer,
            BASE_DIR,
            collection_date=parsed.collection_date,
            index_override=parsed.index_override,
            skip_publish=parsed.local,
        ),
        "coverage": lambda: run_coverage_pipeline(
            parsed.date_to, manager, BASE_DIR,
            older_than=parsed.older_than, reference_fleet=parsed.reference_fleet
        ),
    }

    pipelines = (
        all_pipelines
        if parsed.only == "all"
        else {parsed.only: all_pipelines[parsed.only]}
    )

    failure_registry.reset()
    had_exception = False

    with ThreadPoolExecutor(max_workers=len(pipelines)) as executor:
        futures = {executor.submit(fn): name for name, fn in pipelines.items()}

        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                print(f"[{name}] terminé avec succès : {result}")
            except Exception as exc:
                had_exception = True
                print(f"[{name}] a échoué : {exc}", file=sys.stderr)

    if failure_registry.has_failures:
        print(
            f"[WARNING] Échecs partiels détectés (fallback appliqué) :\n"
            f"{failure_registry.summary()}",
            file=sys.stderr,
        )

    if had_exception or failure_registry.has_failures:
        sys.exit(1)


if __name__ == "__main__":
    main()