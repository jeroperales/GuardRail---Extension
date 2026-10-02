import asyncio
import hashlib
import os
import tempfile
from enum import Enum

import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    NO_THREATS_FOUND = "no_threats_found"
    INCONCLUSIVE = "inconclusive"
    PENDING = "pending"
    NOT_FOUND = "not_found"
    ERROR = "error"


class ScanResult(BaseModel):
    verdict: Verdict
    message: str
    sha256: str | None = None
    detections: int = 0
    engines_completed: int = 0
    engines_total: int = 0
    coverage_pct: float = 0.0
    flagged_by: list[str] = []
    report_url: str | None = None


# --- tunable policy -------------------------------------------------------
MALICIOUS_THRESHOLD = 3
MIN_COVERAGE = 0.60
POLL_INTERVAL = 15   # seconds; free tier allows 4 requests/min. Lower if you have a premium key.
MAX_POLLS = 8        # 8 x 15s = ~2 minutes

load_dotenv()
apiKey = os.getenv("TOTALVIRUS_KEY")
AccountID = os.getenv("ACCOUNT_ID_VIRUSTOTAL")
algorithm = 'sha256'

app = FastAPI()
MAX_SIZE = 32 * 1024 * 1024  # VT's simple upload limit is 32 MB

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,   # "*" and credentials can't be combined
    allow_methods=["*"],
    allow_headers=["*"],
)

zipPassword = ''  # potential password for zips


def getAnalysisID(files):
    r = httpx.post(
        url='https://www.virustotal.com/api/v3/files',
        files=files,
        headers={"x-apikey": apiKey, "accept": "application/json"},
        timeout=60.0
    )
    print(r.status_code)

    if r.status_code == 200:
        print('IT WORKED')
        return r.json()["data"]["id"]

    print('Error occurred.', r.text)
    return None


def getHash(file, algorithm='sha256'):
    hashFunc = hashlib.new(algorithm)
    with open(file, 'rb') as f:
        while chunk := f.read(8192):
            hashFunc.update(chunk)
    return hashFunc.hexdigest()


def file_already_sent(file_path):
    """Returns (True, r) if known, (False, None) if never seen,
    (None, r) if the lookup itself failed (rate limit, auth, etc.)."""
    file_hash = getHash(file_path, algorithm)
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    r = httpx.get(url=url, headers={"x-apikey": apiKey, "accept": "application/json"}, timeout=60)

    if r.status_code == 200:
        print('FILE ALREADY KNOWN TO VIRUSTOTAL')
        return True, r
    if r.status_code == 404:
        print('FILE HAS NOT BEEN SENT YET')
        return False, None
    return None, r


def build_verdict(data: dict | None, status_code: int = 200) -> ScanResult:
    # 1. Transport-level problems
    if status_code == 404:
        return ScanResult(verdict=Verdict.NOT_FOUND,
                          message="File has not been scanned before.")
    if status_code == 429:
        return ScanResult(verdict=Verdict.ERROR,
                          message="Scan service rate limit reached. Try again shortly.")
    if status_code in (401, 403):
        return ScanResult(verdict=Verdict.ERROR,
                          message="Scan service authentication failed.")
    if status_code != 200 or not data or "data" not in data:
        return ScanResult(verdict=Verdict.ERROR,
                          message="Unexpected response from scan service.")

    obj = data["data"]
    attrs = obj.get("attributes", {})
    obj_type = obj.get("type")  # "file" or "analysis"

    # 2. Normalize the two VirusTotal shapes
    if obj_type == "analysis":
        if attrs.get("status") != "completed":
            return ScanResult(verdict=Verdict.PENDING,
                              message="Analysis is still running.")
        stats = attrs.get("stats", {})
        results = attrs.get("results", {})
        sha256 = data.get("meta", {}).get("file_info", {}).get("sha256")
    else:
        stats = attrs.get("last_analysis_stats")
        results = attrs.get("last_analysis_results", {})
        sha256 = attrs.get("sha256") or obj.get("id")
        if not stats or not results:
            return ScanResult(verdict=Verdict.PENDING, sha256=sha256,
                              message="File is known but has no analysis yet.")

    # 3. Count engines
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    completed = (malicious + suspicious
                 + stats.get("undetected", 0) + stats.get("harmless", 0))
    failed = (stats.get("timeout", 0) + stats.get("confirmed-timeout", 0)
              + stats.get("failure", 0))
    attempted = completed + failed
    coverage = completed / attempted if attempted else 0.0

    flagged_by = sorted(
        name for name, r in results.items()
        if r.get("category") in ("malicious", "suspicious")
    )

    base = dict(
        sha256=sha256,
        detections=malicious + suspicious,
        engines_completed=completed,
        engines_total=attempted,
        coverage_pct=round(coverage * 100, 1),
        flagged_by=flagged_by,
        report_url=f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else None,
    )

    # 4. Decide
    if malicious >= MALICIOUS_THRESHOLD:
        return ScanResult(verdict=Verdict.MALICIOUS,
                          message=f"{malicious} engines flagged this file as malicious.",
                          **base)
    if malicious > 0 or suspicious > 0:
        return ScanResult(verdict=Verdict.SUSPICIOUS,
                          message="Some engines flagged this file. Treat with caution.",
                          **base)
    if coverage < MIN_COVERAGE:
        return ScanResult(verdict=Verdict.INCONCLUSIVE,
                          message=(f"No detections, but only {completed} of {attempted} "
                                   "engines completed. Rescan later."),
                          **base)
    return ScanResult(verdict=Verdict.NO_THREATS_FOUND,
                      message="No threats detected by the scanning engines.",
                      **base)


# THE BIG FUNCTION
async def is_file_malicious(file, file_path) -> ScanResult:
    # `file` must be the httpx files dict: {"file": (name, bytes, content_type)}
    was_sent, r = await asyncio.to_thread(file_already_sent, file_path)

    if was_sent is None:  # lookup failed (429 / 401 / 5xx)
        return build_verdict(None, r.status_code)
    if was_sent:
        return build_verdict(r.json(), r.status_code)

    analysis_id = await asyncio.to_thread(getAnalysisID, file)
    if not analysis_id:
        return ScanResult(verdict=Verdict.ERROR,
                           message="Could not submit the file to the scan service (it may be rate-limited).")

    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": apiKey, "accept": "application/json"}

    async with httpx.AsyncClient(timeout=30) as client:
        for _ in range(MAX_POLLS):
            await asyncio.sleep(POLL_INTERVAL)   # a fresh upload is always queued at first
            r = await client.get(url, headers=headers)
            if r.status_code == 429:             # rate limited: wait and retry
                continue
            result = build_verdict(r.json() if r.status_code == 200 else None, r.status_code)
            if result.verdict != Verdict.PENDING:
                return result

    return ScanResult(verdict=Verdict.PENDING,
                      message="Analysis is taking longer than expected. Try again in a minute.")


@app.post("/file", response_model=ScanResult)
async def scan(upload: UploadFile = File(...)):
    content = await upload.read(MAX_SIZE + 1)
    if len(content) > MAX_SIZE:
        raise HTTPException(413, "File too large (32 MB max).")
    if not content:
        raise HTTPException(400, "Empty file.")

    files = {"file": (upload.filename or "upload",
                      content,
                      upload.content_type or "application/octet-stream")}

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(content)
        path = tmp.name
    try:
        return await is_file_malicious(files, path)
    except httpx.HTTPError:
        return ScanResult(verdict=Verdict.ERROR,
                          message="Could not reach the scan service. Check your connection.")
    finally:
        os.remove(path)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)