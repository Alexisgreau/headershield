from fastapi import APIRouter

from .routes_export import router as export_router
from .routes_scan import router as scan_router
from .routes_scans import router as scans_router
from .routes_targets import router as targets_router
from .routes_upload import router as upload_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(scan_router)
api_router.include_router(targets_router)
api_router.include_router(scans_router)
api_router.include_router(export_router)
api_router.include_router(upload_router)

