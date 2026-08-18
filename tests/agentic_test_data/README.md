# Agentic-sandbox test emails

Thirteen benign `.eml` fixtures, each crafted to exercise one capability of the
OneMail analysis sandbox (`agentic/analysis/image/runner.py`). Use them to
confirm the baseline tasks and the agent-selectable tools behave as expected.

## How the sandbox is reached

The sandbox only runs on emails that deterministic **detection flags**, because
`agentic.Case` refuses to wrap an unflagged detection. So every fixture shares a
"malicious envelope" that guarantees flagging independently of its attachment:

- `Authentication-Results: ... spf=fail; dmarc=fail` → fires `auth_failure`
- a spoofed brand display name (`"Microsoft Account Team" <…@ms-account-verify.example>`) → fires `display_name_spoof`
- an off-domain credential link in the body → fires `credential_url`

The attachment is then what drives the sandbox. Every fixture verified as
`flagged=True` before shipping.

## Running one through the pipeline

```python
from detection import DetectionEngine, Email
from agentic import Case
from agentic.analysis import Analyzer, DockerSandbox   # see scripts/investigate_email.py

raw = open("08_office_macro.eml", "rb").read()
detection = DetectionEngine().detect(Email(file="08_office_macro.eml", content=raw))
case = Case(email=Email(file="08_office_macro.eml", content=raw), detection=detection)
analysis = Analyzer(sandbox=DockerSandbox, agent=your_agent).analyze(case)
```

`scripts/investigate_email.py` wires this together end to end (Docker image +
model). Remember to build the image first:
`docker build -t onemail-analysis:latest agentic/analysis/image`.

## What each file tests

Baseline tasks (`extract`, `profile`, `identify`, `strings`, `yara`,
`antivirus`) run automatically on **every** artifact, so each fixture exercises
those too; the table lists the capability it is *designed* to demonstrate.

| File | Capability | What the sandbox should show |
| --- | --- | --- |
| `01_extract_multi.eml` | extract / reconcile | Two artifacts (`payload.bin`, `notes.txt`) extracted; hashes reconciled against detection metadata. |
| `02_profile_type_mismatch.eml` | profile | `statement.pdf` begins with `MZ`; profile flags a declared-vs-actual type mismatch and high entropy. |
| `03_identify_disguised.eml` | identify | `logo.dat` is reported by `file` as `image/png`, not the `.dat` its name implies. |
| `04_strings_iocs.eml` | strings | Readable C2 URL, drop email, and a base64-looking token surface in the strings output. |
| `05_yara_powershell.eml` | yara | Matches `Suspicious_PowerShell_Encoded_Command` (`powershell` + `-EncodedCommand`). |
| `06_antivirus_eicar.eml` | antivirus | Standard **EICAR** test file → ClamAV reports FOUND *if signatures are present*; otherwise an antivirus coverage gap. |
| `07_archive_zip.eml` | archive | `7z l` lists `readme.txt` and a nested `data/` folder without extracting. |
| `08_office_macro.eml` | office | A real OLE spreadsheet; `AutoOpen`/`Workbook_Open` tokens match `Suspicious_Office_AutoOpen`, and `olevba` runs. See note below. |
| `09_pdf_openaction.eml` | pdf | Valid one-page PDF carrying `/OpenAction` + `/JavaScript`; pypdf reads the page. |
| `10_pe_executable.eml` | pe | Minimal valid PE32; pefile reads `machine` (i386) and the `.text` section. |
| `11_script_tokens.eml` | script | Contains `powershell`, `invoke-expression`, `FromBase64String`, `WScript.Shell`, `cmd.exe`. |
| `12_embedded_polyglot.eml` | embedded | JPEG followed by a `PK\x03\x04` zip signature at a non-zero offset. |
| `13_metadata_exif.eml` | metadata | ExifTool reads `Software`, `Make`, `UserComment`, and GPS fields. |

## Notes

- **Everything here is inert.** EICAR is the industry-standard antivirus test
  string; the PE is headers-only with no runnable code; the "macro" and "script"
  files are tokens as text, never executed. The sandbox only inspects them
  statically.
- **EICAR needs signatures.** The `antivirus` task only reports a hit when a
  ClamAV database is present in the image (`agentic/analysis/image/signatures/clamav/`).
  Without it the task records a coverage gap — which is itself a valid thing to
  observe.
- **`office` / olevba.** The fixture is a genuine OLE document so `identify` and
  `olevba` treat it as Office, and the macro tokens trip the baseline YARA rule.
  It contains no compiled VBA project, so `olevba` reports *no macros*. To also
  exercise olevba's VBA parser, drop in a real macro-bearing document in place of
  the attachment.
- **Regenerate or tweak** with `make_agentic_samples.py` (kept alongside these
  files); edit the fixture table there to add or change cases.
