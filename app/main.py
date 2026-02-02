from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .api.v1 import api_router
from .api.web.routes_pages import router as pages_router
from .core.database import init_db
from .core.rate_limit import SimpleRateLimiter

from contextlib import asynccontextmanager
import os

# Nouveau système de gestion du démarrage/arrêt
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Au démarrage
    print("🚀 Démarrage de HeaderShield...")
    init_db() # Ou await init_db() si c'est asynchrone
    yield
    # À l'arrêt (optionnel)
    print("🛑 Arrêt...")

def create_app() -> FastAPI:
    # On injecte le lifespan ici
    app = FastAPI(title="HeaderShield", lifespan=lifespan)
    
    # Sécurité via variable d'environnement
    app.add_middleware(SessionMiddleware, secret_key="hs_dev_secret")
    
    app.include_router(api_router)
    app.include_router(pages_router)
    
    # Petite sécurité pour éviter le crash si le dossier static n'existe pas
    if os.path.exists("app/web/static"):
        app.mount("/static", StaticFiles(directory="app/web/static"), name="static")
    
    # ... le reste de votre middleware rate_limit est bon ...
    
    return app

app = create_app()
