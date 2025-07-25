import os
import uuid
from typing import Optional

import httpx
from fastapi import FastAPI, Depends, HTTPException, status, Request, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# --- Cargar variables del entorno ---
load_dotenv()

# --- Configuración del Gateway ---
HIDDEN_API_URL = os.getenv("HIDDEN_API_URL")
if not HIDDEN_API_URL:
    raise ValueError("La variable de entorno HIDDEN_API_URL no está configurada.")

# --- Seguridad ---
# Se define el esquema de seguridad para que Swagger UI muestre el botón "Authorize".
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# --- Esquemas Pydantic (DTOs) ---
# Solo se necesita el esquema para el login.
class LoginUser(BaseModel):
    username: str
    password: str

# --- Router de Autenticación ---
auth_router = APIRouter(prefix="/auth", tags=["authentication"])

@auth_router.post("/login", response_model=dict)
async def login(
    request: Request
):
    
    content_type = request.headers.get('content-type')
    
    if 'application/json' in content_type:
        json_body = await request.json()
        user_data = LoginUser.model_validate(json_body)
        username = user_data.username
        password = user_data.password
    elif 'application/x-www-form-urlencoded' in content_type:
        form_data = await request.form()
        username = form_data.get('username')
        password = form_data.get('password')
    else:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Content-Type no soportado. Usar 'application/json' o 'application/x-www-form-urlencoded'."
        )
    login_data = {"username": form_data.username, "password": form_data.password}
    async with httpx.AsyncClient() as client:
        try:
            # Se reenvían las credenciales a la API oculta.
            response = await client.post(f"{HIDDEN_API_URL}/api/v1/auth/login", json=login_data)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=e.response.status_code, 
                detail=e.response.json().get("detail", "Credenciales incorrectas"), 
                headers={"WWW-Authenticate": "Bearer"}
            )
        except httpx.RequestError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
                detail="El servicio de login interno no está disponible."
            )

# --- Aplicación FastAPI Principal ---
app = FastAPI(title="Gateway de Autenticación")

# Incluimos el router de autenticación en la aplicación principal
app.include_router(auth_router)

# --- Configuracion de CORS ---
allowed_origins = os.getenv("ALLOWED_ORIGINS", "").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
