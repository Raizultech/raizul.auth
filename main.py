import os
import uuid
from typing import Optional

import httpx
from fastapi import FastAPI, Depends, HTTPException, status, Request, APIRouter
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# --- Cargar variables del entorno ---
load_dotenv()

# --- Configuración del Gateway ---
HIDDEN_API_URL = os.getenv("HIDDEN_API_URL")
print(f"URL de la API oculta: {HIDDEN_API_URL}")
if not HIDDEN_API_URL:
    raise ValueError("La variable de entorno HIDDEN_API_URL no está configurada.")

# --- Seguridad ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# --- Esquemas Pydantic (DTOs) ---
# Definen la interfaz con el cliente final.

class RegisterUser(BaseModel):
    username: str
    password: str = Field(..., min_length=8)
    tenant_id: uuid.UUID
    role_id: uuid.UUID
    is_active: bool = True

class LoginUser(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    # Esquema para las respuestas del endpoint /me.
    id: uuid.UUID
    username: str
    tenant_id: uuid.UUID
    role_id: uuid.UUID
    is_active: bool
    
    class Config:
        from_attributes = True

# --- Dependencia de Seguridad ---
async def get_current_user_from_hidden_api(request: Request) -> dict:
    """
    Esta dependencia protege los endpoints. Propaga el token a la API oculta para su validación.
    Si el token es válido, la API oculta devuelve los datos del usuario.
    Si no, devuelve un error 401, que nosotros propagamos.
    """
    authorization: str = request.headers.get("Authorization")
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No se proporcionó token de autorización.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    headers = {"Authorization": authorization}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{HIDDEN_API_URL}/auth/login", headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=e.response.status_code,
                detail=e.response.json().get("detail", "Error de autenticación"),
                headers={"WWW-Authenticate": "Bearer"},
            )
        except httpx.RequestError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="El servicio de autenticación interno no está disponible.",
            )

# --- Router de Autenticación ---
auth_router = APIRouter(prefix="/auth", tags=["authentication"])

@router.post("/login", response_model=dict)
async def login_for_access_token(request: Request, db: Session = Depends(get_db)):
    """
    Acepta credenciales en formato JSON o Form-Data para generar un token de acceso.
    """
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

    user = user_crud.authenticate(db, username=username, password=password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas o usuario inactivo"
        )
    
    token_data = {"sub": str(user.id), "tenant_id": str(user.tenant_id), "role_id": str(user.role_id)}
    access_token = create_access_token(data=token_data)
    
    return {"access_token": access_token, "token_type": "bearer"}


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

