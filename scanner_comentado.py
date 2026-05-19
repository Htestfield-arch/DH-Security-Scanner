import os         # Para manejar rutas y archivos del sistema.
import json       # Para leer y escribir archivos JSON (config, token, etc.).
import base64     # Para decodificar el contenido de correos en Gmail (payload base64).
import threading  # Para ejecutar el análisis en segundo plano sin bloquear la interfaz.
import tkinter as tk  # Para la interfaz gráfica de usuario (GUI).
from tkinter import scrolledtext, messagebox  # Widgets adicionales (cuadro de log y mensajes).

import requests     # Para enviar alertas de seguridad al webhook HTTP.
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build  # Para interactuar de forma segura con la API de Gmail.

# =============================================================================
# ENTORNO Y CONFIGURACIÓN DE RUTAS DE ARCHIVOS
# =============================================================================

# Intenta obtener la ruta base del archivo actual; si falla, usa el directorio actual.
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    BASE_DIR = os.getcwd()

# Definimos rutas de archivos importantes para la auditoría cloud.
FILE_CLIENT_SECRET = os.path.join(BASE_DIR, "client_secret.json")  # Credenciales OAuth de Google.
FILE_TOKEN = os.path.join(BASE_DIR, "token.json")                  # Token de acceso de Gmail.
FILE_ALERTS = os.path.join(BASE_DIR, "alertas.txt")                # Archivo local para registrar alertas.
FILE_CONFIG = os.path.join(BASE_DIR, "config.json")                # Archivo de configuración de políticas de seguridad.

# Alcances de permisos de Gmail (Acceso de solo lectura para auditoría pasiva).
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Valores por defecto de configuración y políticas de filtrado de datos (Data Filtering).
DEFAULT_CONFIG = {
    "webhook_url": "https://miwebhook.com/alerta",           # URL de destino para la notificación de incidentes.
    "keywords": ["confidencial", "contraseña", "contrasena"], # Palabras clave sensibles (Prevención de fuga de información - DLP).
    "whitelist_domains": ["google.com"],                      # Dominios de confianza que se ignoran en el análisis.
    "forbidden_ext": [".zip", ".exe", ".bat", ".js"],         # Extensiones de archivos adjuntos potencialmente maliciosos.
    "dark_mode": True                                         # Estética visual de la interfaz.
}

# =============================================================================
# CLASE PRINCIPAL: MOTOR DE AUDITORÍA CLOUD DE CORREO ELECTRONICO
# =============================================================================

class GmailSecurityScanner:
    """
    Motor principal encargado de gestionar la interfaz gráfica y de procesar las
    reglas de detección de amenazas, fuga de datos y adjuntos peligrosos en Gmail.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("BuscadorDH - Gmail Security Scanner")
        self.root.geometry("820x860")         # Tamaño inicial de la ventana.
        self.root.minsize(820, 860)          # Tamaño mínimo de seguridad.

        # Control de estado del hilo de análisis de correos.
        self.running = False
        self.scan_thread = None
        self.ui_lock = threading.Lock()      # Asegura accesos seguros a la interfaz desde hilos secundarios.

        # Carga de políticas de seguridad desde archivo local o valores por defecto.
        self.config = self.load_config()
        self.webhook_url = self.config.get("webhook_url", DEFAULT_CONFIG["webhook_url"])

    def load_config(self):
        """
        Carga la configuración de auditoría. Si no existe el archivo config.json,
        genera las directivas por defecto.
        """
        if not os.path.exists(FILE_CONFIG):
            try:
                with open(FILE_CONFIG, "w", encoding="utf-8") as f:
                    json.dump(DEFAULT_CONFIG, f, indent=4)
                return DEFAULT_CONFIG
            except Exception:
                return DEFAULT_CONFIG
        try:
            with open(FILE_CONFIG, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return DEFAULT_CONFIG

# =============================================================================
# NOTA PARA DESARROLLADOR: Este código se enfoca estrictamente en Seguridad de Correo 
# Electrónico (Email Security & DLP) y no en escaneo de red por sockets IP/TCP.
# =============================================================================
