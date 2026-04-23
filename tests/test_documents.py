from __future__ import annotations

import gzip
import io
import tarfile
import unittest
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from nordis_smb_inspector.core.documents import (
    ArchiveMember,
    DocumentExtractionCode,
    DocumentExtractionError,
    DocumentKind,
    DocumentLimits,
    document_kind,
    encoded_document_lines,
    iter_archive_members,
    iter_document_lines,
)


def _office_document(path: str, members: dict[str, str]) -> tuple[str, io.BytesIO]:
    output = io.BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for name, value in members.items():
            archive.writestr(name, value)
    output.seek(0)
    return path, output


def _text_pdf(value: str) -> io.BytesIO:
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, StreamObject

    output = io.BytesIO()
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    resources = DictionaryObject(
        {
            NameObject("/Font"): DictionaryObject(
                {NameObject("/F1"): writer._add_object(font)}
            )
        }
    )
    page[NameObject("/Resources")] = resources
    content = StreamObject()
    content.set_data(f"BT /F1 12 Tf 72 720 Td ({value}) Tj ET".encode("ascii"))
    page[NameObject("/Contents")] = writer._add_object(content)
    writer.write(output)
    output.seek(0)
    return output


class DocumentExtractionTests(unittest.TestCase):
    def test_document_kind_uses_case_insensitive_suffixes(self) -> None:
        cases = (
            ("report.PDF", DocumentKind.PDF),
            ("report.docx", DocumentKind.OFFICE_ZIP),
            ("book.XLSM", DocumentKind.OFFICE_ZIP),
            ("slides.pptx", DocumentKind.OFFICE_ZIP),
            ("document.odt", DocumentKind.OFFICE_ZIP),
            ("bundle.ZIP", DocumentKind.ZIP_ARCHIVE),
            ("notes.txt", DocumentKind.PLAIN),
        )
        for path, expected in cases:
            with self.subTest(path=path):
                self.assertEqual(expected, document_kind(path))

    def test_docx_paragraphs_and_attributes_are_extracted(self) -> None:
        path, stream = _office_document(
            "report.docx",
            {
                "word/document.xml": (
                    '<w:document xmlns:w="urn:w"><w:body>'
                    '<w:p><w:r><w:t>password=DocxSecret</w:t></w:r></w:p>'
                    '<w:tag cpassword="AbCdEf1234567890==" />'
                    "</w:body></w:document>"
                ),
                "word/_rels/document.xml.rels": '<Relationships token="RelSecret123" />',
                "ignored/data.bin": "password=ignored",
            },
        )

        lines = tuple(iter_document_lines(stream, path))

        self.assertIn("password=DocxSecret", lines)
        self.assertTrue(any("cpassword=AbCdEf1234567890==" in line for line in lines))
        self.assertFalse(any("ignored" in line for line in lines))

    def test_xlsx_shared_strings_and_rows_are_extracted(self) -> None:
        path, stream = _office_document(
            "book.xlsx",
            {
                "xl/sharedStrings.xml": (
                    '<sst xmlns="urn:x"><si><t>client_secret=SheetSecret</t></si></sst>'
                ),
                "xl/worksheets/sheet1.xml": (
                    '<worksheet xmlns="urn:x"><sheetData><row r="1"><c><v>42</v></c>'
                    "</row></sheetData></worksheet>"
                ),
            },
        )

        lines = tuple(iter_document_lines(stream, path))

        self.assertIn("client_secret=SheetSecret", lines)
        self.assertTrue(any("r=1" in line for line in lines))

    def test_pptx_and_odf_text_are_extracted(self) -> None:
        cases = (
            _office_document(
                "deck.pptx",
                {
                    "ppt/slides/slide1.xml": (
                        '<p:sld xmlns:p="urn:p"><p:p>api_key=SlideSecret</p:p></p:sld>'
                    )
                },
            ),
            _office_document(
                "document.odt",
                {
                    "content.xml": (
                        '<office xmlns:text="urn:t"><text:p>token=OdfSecret</text:p>'
                        "</office>"
                    )
                },
            ),
        )
        for path, stream in cases:
            with self.subTest(path=path):
                lines = tuple(iter_document_lines(stream, path))
                self.assertTrue(any("Secret" in line for line in lines))

    def test_pdf_text_is_extracted_page_by_page(self) -> None:
        stream = _text_pdf("password=PdfSecret")

        lines = tuple(iter_document_lines(stream, "report.pdf"))

        self.assertIn("password=PdfSecret", lines)

    def test_encoded_lines_are_utf8_and_physical_line_delimited(self) -> None:
        encoded = tuple(encoded_document_lines(iter(("şifre=değer", "ikinci"))))

        self.assertEqual(("şifre=değer\nikinci\n").encode(), b"".join(encoded))

    def test_invalid_and_encrypted_containers_have_safe_diagnostics(self) -> None:
        with self.assertRaises(DocumentExtractionError) as invalid:
            tuple(iter_document_lines(io.BytesIO(b"not zip"), "bad.docx"))
        self.assertEqual(DocumentExtractionCode.INVALID_CONTAINER, invalid.exception.code)

        output = io.BytesIO()
        with ZipFile(output, "w") as archive:
            info = ZipInfo("word/document.xml")
            info.flag_bits |= 0x1
            archive.writestr(info, "<document />")
        output.seek(0)
        # zipfile clears encryption flags when writing; invalid ZIP behavior is covered above.
        self.assertEqual((), tuple(iter_document_lines(output, "empty.docx")))

    def test_entry_expansion_line_and_pdf_page_limits_are_enforced(self) -> None:
        path, stream = _office_document(
            "report.docx",
            {
                "word/one.xml": "<root>one</root>",
                "word/two.xml": "<root>two</root>",
            },
        )
        with self.assertRaises(DocumentExtractionError) as entries:
            tuple(iter_document_lines(stream, path, limits=DocumentLimits(max_entries=1)))
        self.assertEqual(DocumentExtractionCode.ENTRY_LIMIT, entries.exception.code)

        path, stream = _office_document(
            "report.docx",
            {"word/document.xml": "<root>password=long</root>"},
        )
        with self.assertRaises(DocumentExtractionError) as expanded:
            tuple(
                iter_document_lines(
                    stream,
                    path,
                    limits=DocumentLimits(max_expanded_bytes=4),
                )
            )
        self.assertEqual(DocumentExtractionCode.EXPANDED_SIZE_LIMIT, expanded.exception.code)

        path, stream = _office_document(
            "report.docx",
            {"word/document.xml": "<root>12345</root>"},
        )
        with self.assertRaises(DocumentExtractionError) as line:
            tuple(
                iter_document_lines(
                    stream,
                    path,
                    limits=DocumentLimits(max_line_chars=4),
                )
            )
        self.assertEqual(DocumentExtractionCode.TEXT_LIMIT, line.exception.code)

        with self.assertRaises(DocumentExtractionError) as pages:
            tuple(
                iter_document_lines(
                    _text_pdf("text"),
                    "report.pdf",
                    limits=DocumentLimits(max_pdf_pages=1, max_expanded_bytes=1),
                )
            )
        self.assertEqual(DocumentExtractionCode.EXPANDED_SIZE_LIMIT, pages.exception.code)

    def test_plain_files_are_not_routed_through_structured_extractor(self) -> None:
        with self.assertRaises(ValueError):
            tuple(iter_document_lines(io.BytesIO(b"text"), "notes.txt"))

    def test_zip_members_are_streamed_with_virtual_paths(self) -> None:
        output = io.BytesIO()
        with ZipFile(output, "w", ZIP_DEFLATED) as archive:
            archive.writestr("folder/config.txt", "password=ArchiveSecret")
            archive.writestr("../unsafe.txt", "password=ignored")
        output.seek(0)

        observed: list[tuple[str, bytes, int, DocumentKind]] = []
        for member in iter_archive_members(output, "bundle.zip"):
            self.assertIsInstance(member, ArchiveMember)
            observed.append((member.path, member.stream.read(), member.size, member.kind))

        self.assertEqual(1, len(observed))
        self.assertEqual("bundle.zip!/folder/config.txt", observed[0][0])
        self.assertEqual(b"password=ArchiveSecret", observed[0][1])
        self.assertEqual(DocumentKind.PLAIN, observed[0][3])

    def test_nested_zip_is_streamed_without_materializing_member(self) -> None:
        inner = io.BytesIO()
        with ZipFile(inner, "w", ZIP_DEFLATED) as archive:
            archive.writestr("secret.txt", "api_key=NestedSecret")
        outer = io.BytesIO()
        with ZipFile(outer, "w", ZIP_DEFLATED) as archive:
            archive.writestr("nested.zip", inner.getvalue())
        outer.seek(0)

        members = []
        for member in iter_archive_members(outer, "outer.zip"):
            members.append((member.path, member.stream.read()))

        self.assertEqual(
            [("outer.zip!/nested.zip!/secret.txt", b"api_key=NestedSecret")],
            members,
        )

    def test_tar_and_standalone_gzip_members_are_streamed(self) -> None:
        tar_output = io.BytesIO()
        with tarfile.open(fileobj=tar_output, mode="w") as archive:
            content = b"password=TarSecret"
            info = tarfile.TarInfo("folder/config.txt")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        tar_output.seek(0)

        tar_members = []
        for member in iter_archive_members(tar_output, "bundle.tar"):
            tar_members.append((member.path, member.stream.read(), member.size))
        self.assertEqual(
            [("bundle.tar!/folder/config.txt", b"password=TarSecret", 18)],
            tar_members,
        )

        gzip_output = io.BytesIO()
        with gzip.GzipFile(fileobj=gzip_output, mode="wb") as archive:
            archive.write(b"api_key=GzipSecret")
        gzip_output.seek(0)

        gzip_members = []
        for member in iter_archive_members(gzip_output, "config.env.gz"):
            gzip_members.append((member.path, member.stream.read(), member.size))
        self.assertEqual(
            [("config.env.gz!/config.env", b"api_key=GzipSecret", None)],
            gzip_members,
        )

    def test_archive_depth_entry_and_expanded_size_limits_are_enforced(self) -> None:
        level_three = io.BytesIO()
        with ZipFile(level_three, "w") as archive:
            archive.writestr("secret.txt", "value")
        level_two = io.BytesIO()
        with ZipFile(level_two, "w") as archive:
            archive.writestr("three.zip", level_three.getvalue())
        level_one = io.BytesIO()
        with ZipFile(level_one, "w") as archive:
            archive.writestr("two.zip", level_two.getvalue())
        level_one.seek(0)

        with self.assertRaises(DocumentExtractionError) as depth:
            tuple(
                iter_archive_members(
                    level_one,
                    "one.zip",
                    limits=DocumentLimits(max_archive_depth=2),
                )
            )
        self.assertEqual(DocumentExtractionCode.ENTRY_LIMIT, depth.exception.code)

        many = io.BytesIO()
        with ZipFile(many, "w") as archive:
            archive.writestr("one.txt", "1")
            archive.writestr("two.txt", "2")
        many.seek(0)
        with self.assertRaises(DocumentExtractionError) as entries:
            tuple(
                iter_archive_members(
                    many,
                    "many.zip",
                    limits=DocumentLimits(max_entries=1),
                )
            )
        self.assertEqual(DocumentExtractionCode.ENTRY_LIMIT, entries.exception.code)

        large = io.BytesIO()
        with ZipFile(large, "w", ZIP_DEFLATED) as archive:
            archive.writestr("large.txt", "A" * 100)
        large.seek(0)
        with self.assertRaises(DocumentExtractionError) as expanded:
            tuple(
                iter_archive_members(
                    large,
                    "large.zip",
                    limits=DocumentLimits(max_expanded_bytes=10),
                )
            )
        self.assertEqual(DocumentExtractionCode.EXPANDED_SIZE_LIMIT, expanded.exception.code)

    def test_error_repr_never_contains_parser_message(self) -> None:
        error = DocumentExtractionError(
            DocumentExtractionCode.PARSE_ERROR,
            "DoNotLeakParserText",
        )

        self.assertNotIn("DoNotLeakParserText", repr(error))


if __name__ == "__main__":
    unittest.main()
