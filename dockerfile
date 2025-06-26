# Imagen base ligera con Python
FROM python:3.11-slim

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar solo archivos necesarios primero para cacheo eficiente
COPY requirements.txt .

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código
COPY . .

# Exponer el puerto estándar para FastAPI
EXPOSE 8080

# Comando para ejecutar FastAPI usando Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
