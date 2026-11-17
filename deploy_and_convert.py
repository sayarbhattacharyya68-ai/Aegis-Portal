"""Generate the academic paper DOCX without deploying or pushing code.

This script intentionally performs no Git operations and never publishes files.
"""

from pathlib import Path


def create_docx() -> Path | None:
    try:
        from docx import Document
    except ImportError:
        print("python-docx is not installed. Install it with: python -m pip install python-docx")
        return None

    project_dir = Path(__file__).resolve().parent
    text_path = project_dir / "Aegis_Portal_IEEE_Paper.txt"
    docx_path = project_dir / "Aegis_Portal_IEEE_Paper.docx"
    if not text_path.is_file():
        print(f"Source document not found: {text_path.name}")
        return None

    document = Document()
    with text_path.open("r", encoding="utf-8") as source:
        for line in source:
            document.add_paragraph(line.rstrip())
    document.save(docx_path)
    print(f"Created: {docx_path.name}")
    return docx_path


if __name__ == "__main__":
    create_docx()