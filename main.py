import os
import uuid
from typing import Optional

import httpx
from fastapi import FastAPI, Depends, HTTPException, status, Request, APIRouter
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# --- Cargar variables del entorno ---
load_dotenv()

# --- Configuración del Gateway ---
# La URL de tu API oculta que maneja toda la lógica de negocio y base de datos.
HIDDEN_API_URL = os.getenv("HIDDEN_API_URL")
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
            # Hacemos la llamada al endpoint /auth/me de la API oculta para validar el token.
            response = await client.get(f"{HIDDEN_API_URL}/auth/me", headers=headers)
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

@auth_router.post("/register", response_model=dict, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: RegisterUser):
    """Recibe los datos de registro y los reenvía a la API oculta."""
    async with httpx.AsyncClient() as client:
        try:
            # CORREGIDO: Se añadió una '/' entre la URL base y la ruta.
            print(f"{HIDDEN_API_URL}")
            response = await client.post(f"{HIDDEN_API_URL}/api/v1/users/", json=user_data.model_dump(mode='json'))
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.json().get("detail", "Error en el registro"))
        except httpx.RequestError:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="El servicio de registro interno no está disponible.")

@auth_router.post("/login", response_model=dict)
async def login(user_data: LoginUser):
    """Recibe las credenciales, las reenvía a la API oculta y devuelve el token JWT."""
    async with httpx.AsyncClient() as client:
        try:
            # CORREGIDO: Se añadió una '/' entre la URL base y la ruta.
            response = await client.post(f"{HIDDEN_API_URL}/api/v1/auth/login", json=user_data.model_dump())
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.json().get("detail", "Credenciales incorrectas"), headers={"WWW-Authenticate": "Bearer"})
        except httpx.RequestError:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="El servicio de login interno no está disponible.")

@auth_router.get("/me", response_model=UserResponse)
def read_users_me(current_user: dict = Depends(get_current_user_from_hidden_api)):
    """
    Endpoint protegido que devuelve la información del usuario actual.
    La dependencia 'get_current_user_from_hidden_api' hace todo el trabajo de validación.
    """
    return current_user

# --- Aplicación FastAPI Principal ---
app = FastAPI(title="Gateway de Autenticación")

# Incluimos el router de autenticación en la aplicación principal
app.include_router(auth_router)

