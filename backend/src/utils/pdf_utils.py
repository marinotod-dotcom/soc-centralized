from pathlib import Path
from weasyprint import HTML

def generate_pdf(html_content: str, output_path: Path, base_url: Path) -> None:
    HTML(string=html_content, base_url=str(base_url)).write_pdf(str(output_path))