import os
import uuid
from typing import Optional

import httpx
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# --- Cargar variables del entorno ---
load_dotenv()

# --- Configuración del Gateway --
HIDDEN_API_URL = os.getenv("HIDDEN_API_URL")
if not HIDDEN_API_URL:
    raise ValueError("La variable de entorno HIDDEN_API_URL no está configurada.")

# --- Seguridad ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# --- Esquemas Pydantic (DTOs) ---
# Estos esquemas no cambian, ya que definen la interfaz con el cliente final.
class RegisterUser(BaseModel):
    username: str
    password: str = Field(..., min_length=8, description="La contraseña debe tener al menos 8 caracteres.")
    tenant_id: uuid.UUID
    role_id: uuid.UUID
    is_active: bool = True

class LoginUser(BaseModel):
    username: str
    password: str

# --- Dependencia de Seguridad (Refactorizada) ---
async def get_current_user_from_hidden_api(request: Request) -> dict:
    """
    Esta dependencia protege los endpoints. En lugar de consultar una base de datos local,
    propaga el token a la API oculta para su validación.

    Si el token es válido, la API oculta devuelve los datos del usuario.
    Si no, devuelve un error 401, que nosotros propagamos.
    """
    # Extraemos el header de autorización completo de la petición original.
    authorization: str = request.headers.get("Authorization")
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No se proporcionó token de autorización.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Preparamos los headers para la llamada a la API oculta.
    headers = {"Authorization": authorization}

    async with httpx.AsyncClient() as client:
        try:
            # Hacemos la llamada al endpoint /me de la API oculta.
            response = await client.get(f"{HIDDEN_API_URL}/me", headers=headers)
            
            # Si la API oculta dice que el token no es válido (ej. 401),
            # nosotros también devolvemos un 401.
            response.raise_for_status()
            
            # Si todo está bien, devolvemos los datos del usuario en formato JSON (dict).
            return response.json()

        except httpx.HTTPStatusError as e:
            # Propagamos el código de estado y el detalle del error desde la API oculta.
            raise HTTPException(
                status_code=e.response.status_code,
                detail=e.response.json().get("detail", "Error de autenticación"),
                headers={"WWW-Authenticate": "Bearer"},
            )
        except httpx.RequestError:
            # Error si no se puede conectar con la API oculta.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="El servicio de autenticación interno no está disponible.",
            )

# --- Aplicación FastAPI ---
app = FastAPI(title="Gateway de Autenticación")

@app.post("/register", response_model=dict, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: RegisterUser):
    """
    Recibe los datos de registro y los reenvía a la API oculta.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{HIDDEN_API_URL}/register",
                json=user_data.dict(by_alias=True) # Usamos .dict() para serializar los UUIDs
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=e.response.status_code,
                detail=e.response.json().get("detail", "Error en el registro"),
            )
        except httpx.RequestError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="El servicio de registro interno no está disponible.",
            )

@app.post("/login", response_model=dict)
async def login(user_data: LoginUser):
    """
    Recibe las credenciales, las reenvía a la API oculta para autenticar
    y devuelve el token JWT generado por el servicio oculto.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{HIDDEN_API_URL}/login",
                json=user_data.dict()
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=e.response.status_code,
                detail=e.response.json().get("detail", "Credenciales incorrectas"),
                headers={"WWW-Authenticate": "Bearer"},
            )
        except httpx.RequestError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="El servicio de login interno no está disponible.",
            )

@app.get("/me", response_model=dict)
def read_users_me(current_user: dict = Depends(get_current_user_from_hidden_api)):
    """
    Endpoint protegido que devuelve la información del usuario actual.
    La dependencia 'get_current_user_from_hidden_api' hace todo el trabajo de validación.
    """
    return current_user
