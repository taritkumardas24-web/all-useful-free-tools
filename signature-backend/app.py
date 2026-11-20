import io
import os
import tempfile
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from pyhanko.keys import load_certs_from_pemder\nfrom cryptography import x509\nfrom cryptography.hazmat.primitives import hashes
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_certvalidator import ValidationContext
from pyhanko.sign.validation import validate_pdf_signature

MAX_BYTES = 25 * 1024 * 1024
ROOT_PEM = os.getenv("CCA_ROOT_CERT_PEM", "").strip()\nROOT_SHA256 = os.getenv("CCA_ROOT_SHA256_HEX", "").replace(":", "").replace(" ", "").lower()
ALLOWED_ORIGINS = [
    item.strip()
    for item in os.getenv(
        "ALLOWED_ORIGINS",
        "https://taritkumardas24-web.github.io,http://localhost:5500",
    ).split(",")
    if item.strip()
]

app = FastAPI(title="All Useful Free Tools - PDF Signature Verification API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/health")
def health() -> dict[str, Any]:
    configured = bool(ROOT_PEM.startswith("-----BEGIN CERTIFICATE-----") and "-----END CERTIFICATE-----" in ROOT_PEM and len(ROOT_SHA256) == 64)
    return {
        "status": "ok",
        "verification_engine": "pyHanko",
        "cca_root_configured": configured,
        "green_verified_enabled": configured,
    }


def _validate_pdf(data: bytes) -> dict[str, Any]:
    if not ROOT_PEM.startswith("-----BEGIN CERTIFICATE-----") or len(ROOT_SHA256) != 64:
        return {
            "overall": "unverified",
            "green_verified": False,
            "message": "India CCA trust root is not configured. No green Verified result can be issued.",
            "checks": [],
            "signatures": [],
        }

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", encoding="ascii") as cert_file:\n            cert_file.write(ROOT_PEM)\n            cert_file.flush()\n            parsed_root = x509.load_pem_x509_certificate(ROOT_PEM.encode("ascii"))\n            actual_fingerprint = parsed_root.fingerprint(hashes.SHA256()).hex()\n            if actual_fingerprint != ROOT_SHA256:\n                raise ValueError("CCA root SHA-256 fingerprint does not match the independently confirmed pin")\n            roots = list(load_certs_from_pemder([cert_file.name]))
        if not roots:
            raise ValueError("No certificates found in configured trust file")

        reader = PdfFileReader(io.BytesIO(data))
        embedded = reader.embedded_signatures
        if not embedded:
            return {
                "overall": "invalid",
                "green_verified": False,
                "message": "No embedded digital PDF signature was found.",
                "checks": [{"name": "PDF signature", "status": "failed"}],
                "signatures": [],
            }

        results = []
        all_pass = True
        for index, sig in enumerate(embedded, start=1):
            try:
                context = ValidationContext(
                    trust_roots=roots,
                    allow_fetching=True,
                    revocation_mode="hard-fail",
                )
                status = validate_pdf_signature(sig, context)
                passed = bool(status.bottom_line)
                all_pass = all_pass and passed
                details = status.pretty_print_details()
                results.append({
                    "number": index,
                    "field_name": str(getattr(sig, "field_name", "") or f"Signature {index}"),
                    "status": "valid" if passed else "failed_or_unknown",
                    "bottom_line": passed,
                    "details": str(details),
                })
            except Exception as exc:
                all_pass = False
                results.append({
                    "number": index,
                    "field_name": f"Signature {index}",
                    "status": "unknown",
                    "bottom_line": False,
                    "details": f"Validation could not be completed: {type(exc).__name__}",
                })

        return {
            "overall": "valid" if all_pass else "failed_or_unknown",
            "green_verified": bool(all_pass and len(results) > 0),
            "message": (
                "All embedded signatures passed the configured cryptographic, trust and hard-fail revocation checks."
                if all_pass
                else "At least one signature did not pass every configured check. Do not treat this document as verified."
            ),
            "checks": [
                {"name": "Cryptographic signature and document integrity", "status": "passed" if all_pass else "review"},
                {"name": "Configured India CCA trust chain", "status": "passed" if all_pass else "review"},
                {"name": "Revocation check (hard-fail)", "status": "passed" if all_pass else "review"},
            ],
            "signatures": results,
            "note": "This is not an Aadhaar/PAN/caste-record database check. Confirm the CCA root certificate fingerprint out-of-band before production use.",
        }
    except Exception as exc:
        return {
            "overall": "invalid_or_unreadable",
            "green_verified": False,
            "message": "The PDF could not be safely validated.",
            "checks": [{"name": "PDF parsing / validation", "status": "failed"}],
            "signatures": [],
            "error_type": type(exc).__name__,
        }


@app.post("/api/verify")
async def verify(file: UploadFile = File(...)) -> JSONResponse:
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=415, detail="Please upload a PDF file.")
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="PDF exceeds the 25 MB limit.")
    if not data.startswith(b"%PDF-"):
        raise HTTPException(status_code=415, detail="The uploaded file is not a valid PDF header.")
    result = await run_in_threadpool(_validate_pdf, data)
    return JSONResponse(result)
