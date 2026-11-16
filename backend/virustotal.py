"""Compatibility routes for the shared, policy-gated intelligence service."""
from fastapi import APIRouter, Depends, File, Request, UploadFile, HTTPException
from . import intelligence as intel, security_samples as samples
router = APIRouter(prefix="/api/virustotal", dependencies=[Depends(intel.operator)])
MAX_FILE = samples.MAX_BYTES

def _report(raw, sha):
    if raw is not None and (not isinstance(raw, dict) or not isinstance(raw.get("data"), dict)):
        raise HTTPException(502, "VirusTotal returned an invalid report")
    attrs = (raw or {}).get("data", {}).get("attributes", {})
    if not isinstance(attrs, dict):
        raise HTTPException(502, "VirusTotal returned invalid report attributes")
    stats = attrs.get("last_analysis_stats", attrs.get("stats", {}))
    results = attrs.get("last_analysis_results", attrs.get("results", {}))
    if not isinstance(stats, dict) or not isinstance(results, dict):
        raise HTTPException(502, "VirusTotal returned invalid analysis results")
    return {"sha256": sha, "found": raw is not None,
            "status": attrs.get("status", "known" if raw else "unknown"),
            "stats": {name: value for name, value in stats.items() if isinstance(value, int) and not isinstance(value, bool) and value >= 0},
            "analysed_at": attrs.get("last_analysis_date"),
            "detections": [{"engine": str(name)[:120], "category": row.get("category"), "result": str(row.get("result") or "")[:240]}
                           for name, row in list(results.items())[:100] if isinstance(row, dict) and row.get("category") in ("malicious", "suspicious")],
            "url": f"https://www.virustotal.com/gui/file/{sha}",
            "note": "No detections is not proof that a file is safe. Unknown means no report was found."}



@router.get("/settings")
def settings():
    return {**intel.status("virustotal"), "max_file_bytes": MAX_FILE}

@router.post("/settings")
def configure(payload: dict, request: Request):
    intel.secure_transport(request)
    return intel.configure("virustotal", payload)

@router.get("/files/{sha}")
def lookup(sha: str):
    return intel.lookup("virustotal", sha)

@router.post("/check-file")
def check_file(request: Request, file: UploadFile = File(...)):
    return samples.check_file("virustotal", request, file)

@router.delete("/uploads/{token}")
def discard(token: str):
    return samples.cancel("virustotal", token)

@router.post("/uploads/{token}")
def upload(token: str, payload: dict, request: Request):
    return samples.upload("virustotal", token, payload, request)

@router.get("/analyses/{token}")
def analysis(token: str):
    return samples.analysis("virustotal", token)
