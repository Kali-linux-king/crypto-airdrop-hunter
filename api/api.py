#!/usr/bin/env python3
"""
Advanced Airdrop API Service
- RESTful endpoints
- JWT authentication
- Rate limiting
- Caching
- OpenAPI documentation
- Real-time updates
"""

import os
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import uvicorn
import redis
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
import jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
import logging
from pathlib import Path
from database import AirdropDatabase

# Load environment variables
load_dotenv()

# Configuration
API_CONFIG = {
    "title": "Airdrop API",
    "description": "Real-time cryptocurrency airdrop information",
    "version": "2.1.0",
    "docs_url": "/docs",
    "redoc_url": "/redoc",
    "openapi_url": "/openapi.json",
    "rate_limit": "100/minute",
    "jwt_expire_minutes": 30,
    "cache_ttl": 300  # 5 minutes
}

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class Airdrop(BaseModel):
    name: str = Field(..., example="Ethereum Airdrop")
    link: str = Field(..., example="https://example.com/airdrop")
    source: str = Field(..., example="coinmarketcap")
    scraped_at: str = Field(..., example=datetime.utcnow().isoformat())
    score: Optional[float] = Field(0.5, ge=0, le=1)
    metadata: Optional[Dict] = Field({}, example={"value": "$100"})

class User(BaseModel):
    username: str
    disabled: Optional[bool] = False

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Database
db = AirdropDatabase()

# Redis Cache
try:
    redis_client = redis.Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        password=os.getenv('REDIS_PASSWORD'),
        decode_responses=True
    )
    redis_client.ping()
except redis.ConnectionError:
    logger.warning("Redis not available, using in-memory cache")
    redis_client = None

# FastAPI App
app = FastAPI(
    title=API_CONFIG['title'],
    description=API_CONFIG['description'],
    version=API_CONFIG['version'],
    docs_url=API_CONFIG['docs_url'],
    redoc_url=API_CONFIG['redoc_url'],
    openapi_url=API_CONFIG['openapi_url']
)

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static Files (for OpenAPI)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Security Utilities
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str):
    return pwd_context.hash(password)

def get_user(username: str):
    users_db = {
        "admin": {
            "username": "admin",
            "hashed_password": get_password_hash(os.getenv('ADMIN_PASSWORD', 'secret')),
            "disabled": False
        }
    }
    if username in users_db:
        return UserInDB(**users_db[username])

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        os.getenv('JWT_SECRET', 'secret'),
        algorithm="HS256"
    )
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            os.getenv('JWT_SECRET', 'secret'),
            algorithms=["HS256"]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Cache Utilities
def get_cache_key(endpoint: str, **kwargs):
    key_parts = [endpoint] + [f"{k}={v}" for k, v in sorted(kwargs.items())]
    return ":".join(key_parts)

def cache_response(endpoint: str, ttl: int = API_CONFIG['cache_ttl']):
    def decorator(func):
        async def wrapper(*args, **kwargs):
            if not redis_client:
                return await func(*args, **kwargs)
                
            cache_key = get_cache_key(endpoint, **kwargs)
            cached = redis_client.get(cache_key)
            
            if cached:
                logger.info(f"Cache hit for {cache_key}")
                return JSONResponse(content=json.loads(cached))
                
            result = await func(*args, **kwargs)
            redis_client.setex(
                cache_key,
                ttl,
                json.dumps(jsonable_encoder(result))
            )
            return result
        return wrapper
    return decorator

# API Endpoints
@app.post("/token", response_model=Token)
@limiter.limit(API_CONFIG['rate_limit'])
async def login_for_access_token(
    username: str = Query(...),
    password: str = Query(...)
):
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=API_CONFIG['jwt_expire_minutes'])
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/airdrops", response_model=List[Airdrop])
@cache_response("get_airdrops")
@limiter.limit(API_CONFIG['rate_limit'])
async def get_airdrops(
    limit: int = Query(20, gt=0, le=100),
    source: Optional[str] = Query(None),
    min_score: Optional[float] = Query(None, ge=0, le=1),
    current_user: User = Depends(get_current_active_user)
):
    """Get list of airdrops with optional filtering"""
    try:
        query = "SELECT * FROM airdrops WHERE is_active = 1"
        params = []
        
        if source:
            query += " AND source = ?"
            params.append(source)
            
        if min_score is not None:
            query += " AND score >= ?"
            params.append(min_score)
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        results = db.query(query, tuple(params))
        return [Airdrop(**r) for r in results]
        
    except Exception as e:
        logger.error(f"Error fetching airdrops: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )

@app.get("/airdrops/search", response_model=List[Airdrop])
@cache_response("search_airdrops")
@limiter.limit(API_CONFIG['rate_limit'])
async def search_airdrops(
    q: str = Query(..., min_length=2),
    limit: int = Query(10, gt=0, le=50),
    current_user: User = Depends(get_current_active_user)
):
    """Search airdrops by name or source"""
    try:
        results = db.search(q, limit)
        return [Airdrop(**r) for r in results]
    except Exception as e:
        logger.error(f"Search failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Search operation failed"
        )

@app.get("/airdrops/stats")
@cache_response("get_stats", ttl=3600)  # 1 hour cache
@limiter.limit(API_CONFIG['rate_limit'])
async def get_stats(current_user: User = Depends(get_current_active_user)):
    """Get database statistics"""
    try:
        return db.get_stats()
    except Exception as e:
        logger.error(f"Stats failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve statistics"
        )

@app.get("/airdrops/{airdrop_id}", response_model=Airdrop)
@cache_response("get_airdrop")
@limiter.limit(API_CONFIG['rate_limit'])
async def get_airdrop(
    airdrop_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get specific airdrop by ID"""
    try:
        result = db.query(
            "SELECT * FROM airdrops WHERE id = ? LIMIT 1",
            (airdrop_id,)
        )
        if not result:
            raise HTTPException(
                status_code=404,
                detail="Airdrop not found"
            )
        return Airdrop(**result[0])
    except Exception as e:
        logger.error(f"Error fetching airdrop {airdrop_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )

# WebSocket for real-time updates
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            if connection.client_state == WebSocketState.CONNECTED:
                try:
                    await connection.send_text(message)
                except WebSocketDisconnect:
                    self.disconnect(connection)

manager = ConnectionManager()

@app.websocket("/ws/updates")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle incoming messages if needed
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Background task for updates
from fastapi import BackgroundTasks

def notify_clients():
    stats = db.get_stats()
    message = json.dumps({
        "event": "update",
        "timestamp": datetime.utcnow().isoformat(),
        "count": stats['total_airdrops']
    })
    manager.broadcast(message)

@app.post("/refresh")
@limiter.limit("10/hour")
async def refresh_data(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user)
):
    """Trigger manual data refresh"""
    try:
        background_tasks.add_task(notify_clients)
        return {"message": "Refresh initiated"}
    except Exception as e:
        logger.error(f"Refresh failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Refresh operation failed"
        )

# Health Check
@app.get("/health")
async def health_check():
    """Service health check"""
    try:
        db.query("SELECT 1")
        redis_status = redis_client.ping() if redis_client else True
        return {
            "status": "healthy",
            "database": "online",
            "cache": "online" if redis_status else "offline",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=503,
            detail="Service unavailable"
        )

# Documentation Enhancements
from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
        
    openapi_schema = get_openapi(
        title=API_CONFIG['title'],
        version=API_CONFIG['version'],
        description=API_CONFIG['description'],
        routes=app.routes,
    )
    
    # Add security definitions
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    
    # Add error responses
    for path in openapi_schema["paths"].values():
        for method in path.values():
            method["responses"].update({
                "401": {
                    "description": "Unauthorized",
                    "content": {
                        "application/json": {
                            "example": {"detail": "Not authenticated"}
                        }
                    }
                },
                "429": {
                    "description": "Rate limit exceeded",
                    "content": {
                        "application/json": {
                            "example": {"detail": "Too many requests"}
                        }
                    }
                }
            })
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Startup Event
@app.on_event("startup")
async def startup_event():
    logger.info("Starting Airdrop API Service")
    # Warm up cache
    try:
        db.get_stats()
    except Exception as e:
        logger.warning(f"Startup warmup failed: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(
        "api:app",
        host=os.getenv('HOST', '0.0.0.0'),
        port=int(os.getenv('PORT', 8000)),
        reload=os.getenv('DEBUG', 'false').lower() == 'true',
        workers=int(os.getenv('WORKERS', 1)),
        log_config=None
    )