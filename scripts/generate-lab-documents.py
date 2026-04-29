#!/usr/bin/env python3
"""Generate deterministic binary document fixtures for the local SMB lab."""

from __future__ import annotations

import io
import gzip
import sys
import tarfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, StreamObject


def office(path: Path, members: dict[str, str]) -> None:
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)


def pdf(path: Path, text: str) -> None:
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    page[NameObject("/Resources")] = DictionaryObject(
        {
            NameObject("/Font"): DictionaryObject(
                {NameObject("/F1"): writer._add_object(font)}
            )
        }
    )
    content = StreamObject()
    content.set_data(f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("ascii"))
    page[NameObject("/Contents")] = writer._add_object(content)
    with path.open("wb") as destination:
        writer.write(destination)


def archive(path: Path) -> None:
    nested = io.BytesIO()
    with ZipFile(nested, "w", ZIP_DEFLATED) as inner:
        inner.writestr("nested/config.env", "api_key=NORDIS_ZIP_NESTED_CANARY\n")
    with ZipFile(path, "w", ZIP_DEFLATED) as outer:
        outer.writestr("config/app.env", "client_secret=NORDIS_ZIP_CANARY\n")
        outer.writestr("notes/no-match.txt", "ordinary archived text\n")
        outer.writestr("nested.zip", nested.getvalue())


def tar_archive(path: Path) -> None:
    content = b"password=NORDIS_TAR_CANARY\n"
    with tarfile.open(path, "w") as output:
        info = tarfile.TarInfo("configs/tar-secret.env")
        info.size = len(content)
        output.addfile(info, io.BytesIO(content))


def gzip_archive(path: Path) -> None:
    with gzip.open(path, "wb") as output:
        output.write(b"client_secret=NORDIS_GZIP_CANARY\n")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate-lab-documents.py OUTPUT_DIRECTORY")
    root = Path(sys.argv[1])
    root.mkdir(parents=True, exist_ok=True)
    office(
        root / "office-secret.docx",
        {
            "word/document.xml": (
                '<w:document xmlns:w="urn:w"><w:body><w:p><w:r>'
                "<w:t>password=NORDIS_DOCX_CANARY</w:t></w:r></w:p>"
                "</w:body></w:document>"
            )
        },
    )
    office(
        root / "spreadsheet-secret.xlsx",
        {
            "xl/sharedStrings.xml": (
                '<sst xmlns="urn:x"><si><t>client_secret=NORDIS_XLSX_CANARY</t>'
                "</si></sst>"
            )
        },
    )
    office(
        root / "slides-secret.pptx",
        {
            "ppt/slides/slide1.xml": (
                '<p:sld xmlns:p="urn:p"><p:p>api_key=NORDIS_PPTX_CANARY</p:p></p:sld>'
            )
        },
    )
    office(
        root / "odf-secret.odt",
        {
            "content.xml": (
                '<office xmlns:text="urn:text"><text:p>'
                "password=NORDIS_ODT_CANARY</text:p></office>"
            )
        },
    )
    pdf(root / "pdf-secret.pdf", "password=NORDIS_PDF_CANARY")
    archive(root / "archive-secrets.zip")
    tar_archive(root / "archive-secret.tar")
    gzip_archive(root / "gzip-secret.env.gz")
    (root / "legacy-turkish.txt").write_bytes(
        "ŞİFRE=NORDIS_CP1254_CANARY\n".encode("cp1254")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
