#!/usr/bin/env python3
"""Generate benign .eml fixtures that exercise each agentic-sandbox capability.

Every fixture shares a "malicious envelope" (failed authentication + a spoofed
brand display name) so that deterministic detection flags it and it therefore
reaches the sandbox — the sandbox only runs on flagged emails. Each fixture then
carries one attachment crafted to exercise a specific baseline task or agent
tool in agentic/analysis/image/runner.py.

Everything here is inert and safe: header-only files, macro *tokens* as text,
and benign scripts. Nothing is a working exploit; rendering is offline and PE
behaviour is exercised only through CPU/API emulation.

Install fixture dependencies first with ``pip install -e \".[dev]\"``.
Then run:  python make_agentic_samples.py OUTPUT_DIR
"""

import io
import struct
import sys
import tempfile
import zipfile
from email.message import EmailMessage
from pathlib import Path


# --------------------------------------------------------------------------- #
# Shared envelope: guarantees the message is flagged so it reaches the sandbox.
# --------------------------------------------------------------------------- #
def envelope(subject: str, extra_body: str = "") -> EmailMessage:
    message = EmailMessage()
    message["From"] = '"Microsoft Account Team" <security@ms-account-verify.example>'
    message["To"] = "victim@corp.example"
    message["Reply-To"] = "billing@ms-account-verify.example"
    message["Subject"] = subject
    # spf/dmarc failure -> auth_failure; brand display name off-domain ->
    # display_name_spoof; off-domain credential link -> credential_url.
    message["Authentication-Results"] = "mx.corp.example; spf=fail; dkim=fail; dmarc=fail"
    body = (
        "Our records show unusual sign-in activity. Please verify your account "
        "at https://secure-login.account-check.example/verify to avoid suspension.\n"
        + extra_body
    )
    message.set_content(body)
    return message


def attach(message: EmailMessage, data: bytes, filename: str, maintype: str, subtype: str) -> None:
    message.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)


# --------------------------------------------------------------------------- #
# Attachment builders (all benign).
# --------------------------------------------------------------------------- #
def high_entropy_blob(size: int = 4096) -> bytes:
    # Deterministic pseudo-random bytes: high entropy for the profile task,
    # without pulling in os.urandom (keeps output reproducible).
    out = bytearray()
    state = 0x12345678
    for _ in range(size):
        state = (1103515245 * state + 12345) & 0xFFFFFFFF
        out.append((state >> 16) & 0xFF)
    return bytes(out)


def minimal_pe() -> bytes:
    """A structurally valid, non-functional PE32 (headers + empty .text)."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)  # e_lfanew -> PE header at 0x80
    file_hdr = struct.pack(
        "<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x0102  # i386, 1 section, opt-size, chars
    )
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)      # PE32 magic
    struct.pack_into("<I", opt, 16, 0x1000)    # AddressOfEntryPoint
    struct.pack_into("<I", opt, 28, 0x400000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)    # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)     # FileAlignment
    struct.pack_into("<I", opt, 56, 0x2000)    # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)     # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 2)         # Subsystem = GUI
    struct.pack_into("<I", opt, 92, 16)        # NumberOfRvaAndSizes
    section = b".text\x00\x00\x00" + struct.pack(
        "<IIIIIIHHI", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020
    )
    return bytes(dos) + b"PE\x00\x00" + file_hdr + bytes(opt) + section + b"\x00" * 0x200


def ole_office_doc() -> bytes:
    """A real OLE2 spreadsheet carrying macro *tokens* as cell text.

    xlwt emits a genuine Compound File (so `file`/olevba treat it as Office),
    and the AutoOpen / Workbook_Open tokens trip the baseline YARA rule. It
    contains no actual VBA project, so olevba reports no macros — replace with a
    real macro sample to additionally exercise olevba's VBA parser.
    """
    import xlwt

    book = xlwt.Workbook()
    sheet = book.add_sheet("Invoice")
    sheet.write(0, 0, "Enable content to view this protected document.")
    sheet.write(1, 0, "Sub AutoOpen()")
    sheet.write(2, 0, "Private Sub Workbook_Open()")
    sheet.write(3, 0, 'Shell "cmd.exe /c echo benign-fixture", vbHide')
    sheet.write(4, 0, "End Sub")
    buffer = io.BytesIO()
    book.save(buffer)
    return buffer.getvalue()


def pdf_with_openaction() -> bytes:
    """A minimal one-page PDF with an OpenAction JavaScript (benign alert)."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 4 0 R >>",
        b"<< /Length 44 >>\nstream\nBT /F1 12 Tf 20 100 Td (Invoice) Tj ET\nendstream",
        b"<< /Type /Action /S /JavaScript /JS (app.alert('benign fixture: "
        b"see https://account-check.example/verify');) >>",
    ]
    out = bytearray(b"%PDF-1.5\n")
    offsets = []
    for index, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode()
        + f"startxref\n{xref_pos}\n%%EOF".encode()
    )
    return bytes(out)


def benign_zip() -> bytes:
    """A normal zip listing several members, incl. a nested folder."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("readme.txt", "Benign archive fixture for the archive tool.\n")
        archive.writestr("data/report.csv", "id,amount\n1,100\n2,250\n")
        archive.writestr("data/notice.txt", "Nothing dangerous here.\n")
    return buffer.getvalue()


def jpeg_with_exif() -> bytes:
    """A tiny JPEG with EXIF fields for ExifTool to extract."""
    import piexif
    from PIL import Image

    image = Image.new("RGB", (24, 24), (170, 170, 170))
    exif = {
        "0th": {
            piexif.ImageIFD.Software: b"OneMailFixture 1.0",
            piexif.ImageIFD.Make: b"ACME-Camera",
            piexif.ImageIFD.ImageDescription: b"metadata test fixture",
        },
        "Exif": {
            piexif.ExifIFD.UserComment: b"ASCII\x00\x00\x00note: contact eviluser@attacker.example",
        },
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: ((51, 1), (30, 1), (0, 1)),
        },
        "1st": {},
        "thumbnail": None,
    }
    buffer = io.BytesIO()
    image.save(buffer, "jpeg", exif=piexif.dump(exif))
    return buffer.getvalue()


def jpeg_with_embedded_zip() -> bytes:
    """A valid JPEG header followed by an embedded ZIP signature (offset > 0)."""
    base = io.BytesIO()
    from PIL import Image

    Image.new("RGB", (16, 16), (90, 120, 200)).save(base, "jpeg")
    # Append a real (small) zip after the JPEG's EOI, so `embedded` finds a
    # PK\x03\x04 signature at a non-zero offset.
    return base.getvalue() + benign_zip()


def powershell_text() -> bytes:
    """Text that trips the baseline YARA PowerShell rule."""
    return (
        b"REM Benign fixture demonstrating the PowerShell YARA indicator.\r\n"
        b"powershell -EncodedCommand ZQBjAGgAbwAgAGIAZQBuAGkAZwBuAA==\r\n"
    )


def suspicious_script() -> bytes:
    """A benign script carrying the tokens the `script` task scans for."""
    return (
        b"// Benign fixture for the script tool. No real payload.\r\n"
        b'var shell = "WScript.Shell";\r\n'
        b'// tokens: powershell, invoke-expression, FromBase64String, cmd.exe\r\n'
        b'var demo = "powershell -nop -c invoke-expression"; \r\n'
        b'var b64  = "[Convert]::FromBase64String(\'ZWNobw==\')";\r\n'
        b'var cmd  = "cmd.exe /c echo benign";\r\n'
    )


def strings_blob() -> bytes:
    """A binary with readable IOC-like strings for the `strings` task."""
    return (
        b"\x00\x01\x02\x03CONFIG\x00"
        b"c2_url=https://account-check.example/gate\x00"
        b"drop=eviluser@attacker.example\x00"
        b"key=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\x00"
        + high_entropy_blob(512)
    )


def type_mismatch_blob() -> bytes:
    """A file that will be named .pdf but begins with the PE 'MZ' magic."""
    return b"MZ" + b"\x90\x00\x03\x00\x00\x00\x04\x00" + b"\x00" * 240


# --------------------------------------------------------------------------- #
# Fixture table: (filename, subject, builder, attach-as (name, maintype, subtype)).
# --------------------------------------------------------------------------- #
def build_all(out_dir: Path) -> list:
    fixtures = []

    def add(fname, subject, blob, aname, maintype, subtype, note):
        message = envelope(subject)
        attach(message, blob, aname, maintype, subtype)
        path = out_dir / fname
        path.write_bytes(message.as_bytes())
        fixtures.append((fname, note))

    # Baseline tasks -------------------------------------------------------- #
    multi = envelope("Your two documents")
    attach(multi, high_entropy_blob(4096), "payload.bin", "application", "octet-stream")
    attach(multi, b"Plain notes for the reconcile/extract test.\n", "notes.txt", "text", "plain")
    (out_dir / "01_extract_multi.eml").write_bytes(multi.as_bytes())
    fixtures.append(("01_extract_multi.eml", "extract + reconcile: two artifacts of different types"))

    add("02_profile_type_mismatch.eml", "Statement attached",
        type_mismatch_blob(), "statement.pdf", "application", "pdf",
        "profile: extension/declared says PDF, magic bytes are 'MZ' -> type mismatch")

    add("03_identify_disguised.eml", "Photo enclosed",
        (lambda: __import__("io").BytesIO())() and None or _png_bytes(), "logo.dat", "application", "octet-stream",
        "identify: named .dat but `file` reports image/png")

    add("04_strings_iocs.eml", "Config backup",
        strings_blob(), "config.bin", "application", "octet-stream",
        "strings: readable c2 URL, email, and base64-looking token")

    add("05_yara_powershell.eml", "Log excerpt",
        powershell_text(), "log.txt", "text", "plain",
        "yara: matches Suspicious_PowerShell_Encoded_Command")

    # Agent tools ----------------------------------------------------------- #
    add("07_archive_zip.eml", "Shipping documents",
        benign_zip(), "documents.zip", "application", "zip",
        "archive: `7z l` lists members incl. a nested folder")

    add("08_office_macro.eml", "Protected invoice",
        ole_office_doc(), "invoice.xls", "application", "vnd.ms-excel",
        "office: real OLE doc; AutoOpen/Workbook_Open tokens trip baseline yara; olevba runs")

    add("09_pdf_openaction.eml", "Please review the PDF",
        pdf_with_openaction(), "invoice.pdf", "application", "pdf",
        "pdf: valid 1-page PDF with /OpenAction /JavaScript")

    add("10_pe_executable.eml", "Security update",
        minimal_pe(), "update.exe", "application", "octet-stream",
        "pe: minimal valid PE32 -> pefile reads machine + .text section")

    add("11_script_tokens.eml", "Order details",
        suspicious_script(), "order.js", "text", "javascript",
        "script: contains powershell / invoke-expression / FromBase64String / cmd.exe")

    add("12_embedded_polyglot.eml", "Company photo",
        jpeg_with_embedded_zip(), "photo.jpg", "image", "jpeg",
        "embedded: JPEG with a PK\\x03\\x04 zip signature at a non-zero offset")

    add("13_metadata_exif.eml", "Team picture",
        jpeg_with_exif(), "team.jpg", "image", "jpeg",
        "metadata: ExifTool reads Software/Make/UserComment/GPS")

    html = envelope("Account review form")
    html.add_alternative(
        """<!doctype html><html><body><h1>Account review</h1>
        <form action='https://account-check.example/submit'>
        <label>Password <input type='password' name='password'></label>
        </form></body></html>""",
        subtype="html",
    )
    (out_dir / "14_html_render.eml").write_bytes(html.as_bytes())
    fixtures.append(("14_html_render.eml", "render: HTML body is extracted for offline rendering and OCR"))

    return fixtures


def _png_bytes() -> bytes:
    from PIL import Image
    buffer = io.BytesIO()
    Image.new("RGB", (16, 16), (200, 60, 60)).save(buffer, "png")
    return buffer.getvalue()


def generate_all(out_dir: Path) -> list:
    """Build every fixture before publishing any output files."""

    target = out_dir.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{target.name}-", dir=target.parent
    ) as staging_name:
        staging = Path(staging_name)
        fixtures = build_all(staging)
        target.mkdir(parents=True, exist_ok=True)
        for source in staging.iterdir():
            source.replace(target / source.name)
    return fixtures


def main() -> None:
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "agentic-samples")
    fixtures = generate_all(out_dir)
    for name, note in fixtures:
        print(f"  {name:32}  {note}")
    print(f"\nWrote {len(fixtures)} fixtures to {out_dir}/")


if __name__ == "__main__":
    main()
