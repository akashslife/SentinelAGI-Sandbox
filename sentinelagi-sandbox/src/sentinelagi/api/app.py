"""
SentinelAGI FastAPI Application

Main application entry point with middleware, event handlers,
and API route registration.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sentinelagi.api.routes import router
from sentinelagi.core.config import get_settings
from sentinelagi.core.exceptions import SentinelAGIError
from sentinelagi.sandbox.docker_manager import sandbox_manager

# Configure logging
logging.basicConfig(
    level=getattr(logging, get_settings().log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    # Startup
    logger.info("=" * 60)
    logger.info("SentinelAGI Sandbox Starting")
    logger.info(f"Environment: {get_settings().environment}")
    logger.info(f"Version: {get_settings().app_version}")
    logger.info(f"Sandbox Runtime: {get_settings().sandbox.runtime}")
    logger.info(f"Constitutional AI: {get_settings().security.enable_constitutional_ai}")
    logger.info(f"MITRE ATLAS: {get_settings().security.enable_mitre_atlas_mapping}")
    logger.info("=" * 60)
    
    yield
    
    # Shutdown
    logger.info("SentinelAGI Sandbox shutting down...")
    count = await sandbox_manager.cleanup_all()
    logger.info(f"Cleaned up {count} sandbox containers")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    
    app = FastAPI(
        title="SentinelAGI Sandbox API",
        description="""
        Autonomous Agent Containment System API.
        
        Provides endpoints for:
        - Agent creation and management
        - Sandboxed task execution with tool-permission scoping
        - Constitutional AI critique and self-correction
        - Real-time audit logging and monitoring
        - MITRE ATLAS threat mapping
        
        All agent actions are logged to Redis audit streams and
        analyzed for policy violations and privilege escalation.
        """,
        version=get_settings().app_version,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Exception handler for custom exceptions
    @app.exception_handler(SentinelAGIError)
    async def sentinelagi_exception_handler(request: Request, exc: SentinelAGIError):
        return JSONResponse(
            status_code=500,
            content={
                "error": exc.message,
                "error_code": exc.error_code,
                "severity": exc.severity.value,
                "details": exc.details,
            },
        )
    
    # General exception handler
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "detail": str(exc) if get_settings().debug else "Contact administrator",
            },
        )
    
    # Request logging middleware
    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        import time
        
        start = time.time()
        response = await call_next(request)
        duration = time.time() - start
        
        logger.info(
            f"{request.method} {request.url.path} - {response.status_code} - {duration:.3f}s"
        )
        
        return response
    
    # Register routes
    app.include_router(router)
    
    # Root endpoint
    @app.get("/", tags=["root"])
    async def root():
        return {
            "name": "SentinelAGI Sandbox",
            "version": get_settings().app_version,
            "status": "operational",
            "docs": "/docs",
            "environment": get_settings().environment,
        }
    
    return app


# Application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "sentinelagi.api.app:app",
        host="0.0.0.0",
        port=8000,
        reload=get_settings().environment == "development",
        log_level=get_settings().log_level.lower(),
    )
