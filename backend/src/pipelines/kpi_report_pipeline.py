import os
import json
from pathlib import Path
from datetime import datetime
import logging

from src.services.kpi_service import KPIService
from src.services.mail_service import MailService
from src.utils.wazuh_utils import build_smtp_config
from src.utils.date_utils import get_week_label
from src.utils.template_utils import render_template
from src.utils.pdf_utils import generate_pdf
from src.decorador.resilicence_decorador import failure_registry

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path("src/templates")


def run_kpi_report_pipeline(
    date_from: datetime,
    date_to: datetime,
    pretty_print: bool,
    indexer_client,
    manager_client,
    base_dir: Path,
) -> Path:
    kpi_service = KPIService(indexer_client=indexer_client, manager_client=manager_client)
    kpis = kpi_service.compute_all_kpis(date_from, date_to)

    output = {
        "metadata": {
            "date_from": date_from.strftime("%Y-%m-%d %H:%M:%S"),
            "date_to": date_to.strftime("%Y-%m-%d %H:%M:%S"),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "get_week_label": get_week_label(date_to),
            "partial": failure_registry.has_failures,
        },
        "kpis": kpis,
    }

    if pretty_print:
        print(json.dumps(output, indent=2, ensure_ascii=False, default=str))
    else:
        print(json.dumps(output, ensure_ascii=False, default=str))

    if failure_registry.has_failures:
        logger.warning(
            "Rapport KPI généré en mode DÉGRADÉ (%d échec(s)) :\n%s",
            len(failure_registry.failures), failure_registry.summary(),
        )

    html_content = render_template(output)

    reports_dir = base_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    pdf_path = reports_dir / f"KPI_Wazuh_{get_week_label(date_to)}.pdf"
    generate_pdf(html_content=html_content, output_path=pdf_path, base_url=TEMPLATE_DIR)

    print(f"Rapport PDF généré : {pdf_path}")

    smtp_config = build_smtp_config()
    mail_service = MailService(smtp_config)

    subject = f"Rapport KPI Wazuh - {get_week_label(date_to)}"
    body = """
        Bonjour,

        Veuillez trouver ci-joint le rapport KPI Wazuh hebdomadaire.

        Cordialement,
        SOC
        """

    if failure_registry.has_failures:
        subject = f"[PARTIEL] {subject}"
        body += (
            f"\n\nATTENTION : ce rapport est incomplet. "
            f"{len(failure_registry.failures)} indicateur(s) n'ont pas pu être collectés. "
            f"Consultez les logs du service pour le détail.\n"
        )

    mail_service.send_email(
        recipients=os.getenv("SMTP_RECIPIENTS").split(","),
        subject=subject,
        body=body,
        attachment=pdf_path,
    )

    print("Email envoyé avec succès.")
    return pdf_path