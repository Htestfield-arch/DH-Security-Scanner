# Gmail Security Scanner & Webhook Alerts 🛡️

Este proyecto es una herramienta de escritorio desarrollada en Python que utiliza la **API de Gmail** para escanear bandejas de entrada en busca de contenido sensible y alertar automáticamente mediante un archivo local y un **Webhook externo**.

## ✨ Características
- **Búsqueda Dinámica:** Permite añadir palabras clave en tiempo real desde la interfaz.
- **Detección de Adjuntos:** Identifica extensiones de riesgo (`.exe`, `.zip`, etc.).
- **Notificaciones Webhook:** Envía un JSON con los detalles de la alerta a una URL configurada.
- **Whitelist:** Omite dominios seguros para evitar falsos positivos.

## 🚀 Instalación

1. **Clonar el repositorio:**
   bash
   git clone [https://github.com/Htestfield-arch/DH-Security-Scanner](https://github.com/Htestfield-arch/DH-Security-Scanner)
   cd DH-Security-Scanner

2. **Instalar dependencias:**

   pip install google-api-python-client google-auth-oauthlib requests

3. **Configurar Credenciales de Google:**

   Ve a Google Cloud Console. https://console.cloud.google.com/

   Crea un proyecto y habilita la Gmail API.

   Descarga el archivo de credenciales OAuth (App de escritorio) y guárdalo como client_secret.json en la carpeta raíz del proyecto.

🛠️ Uso
Ejecuta el script: python scanner.py.

Autoriza la aplicación en tu navegador (la primera vez).

Añade palabras clave y presiona el boton "Iniciar Monitoreo".

Revisa las alertas en alertas.txt o en tu endpoint de Webhook (lo puedes incluir aparte en el codigo).

⚠️ Seguridad (IMPORTANTE)

Este repositorio no incluye ni debe incluir:

client_secret.json

token.json

alertas.txt

Asegúrate de agregar estos archivos a tu .gitignore antes de realizar un push.

👤 Autor
Daniel Enrique Herrera Ferrer

Especialista IT 

https://www.linkedin.com/in/daniel-herrera-it-specialist/


