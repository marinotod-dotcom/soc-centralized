from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from src.utils.format_utils import format_fr, format_thousands

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def render_template(context: dict) -> str:
    env = Environment(
        loader=FileSystemLoader(str(BASE_DIR / "templates")),
        autoescape=False,
    )

    env.filters["fr"] = format_fr
    env.filters["thousands"] = format_thousands

    template = env.get_template("weekly_report.html")

    return template.render(**context)
