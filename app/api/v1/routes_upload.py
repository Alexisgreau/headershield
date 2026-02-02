from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile

from ...utils.csv_parse import parse_urls_from_csv, parse_urls_from_text

router = APIRouter(tags=["upload"])


@router.post("/upload-urls")
async def upload_urls(file: UploadFile = File(...)) -> dict:
    # on lit tout en mémoire (2 Mo max) et on parse .csv ou .txt
    content_bytes = await file.read()
    if len(content_bytes) > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail={"error": "File too large (max 2MB)"})
    content = content_bytes.decode("utf-8", errors="ignore")
    if file.filename and file.filename.lower().endswith(".csv"):
        urls = parse_urls_from_csv(content)
    else:
        urls = parse_urls_from_text(content)
    return {"count": len(urls), "urls": urls[:1000]}
