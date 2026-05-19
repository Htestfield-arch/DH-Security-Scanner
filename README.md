📌 Gmail Security Scanner – Python 3.11+
Aplicación en Python que se conecta a la API de Gmail mediante OAuth 2.0, analiza los últimos correos del inbox y detecta palabras clave sensibles, adjuntos peligrosos y dominios no confiables.
Genera alertas en archivo de texto y opcionalmente envía notificaciones vía Webhook.

🚀 Características principales
Autenticación OAuth 2.0 con Gmail.

Lectura de los últimos correos del inbox.

Búsqueda de palabras clave en asunto y cuerpo.

Registro de alertas en alertas.txt.

Whitelist de dominios confiables.

Detección de adjuntos peligrosos (.zip, .exe, .bat, .js).

Notificación opcional por Webhook.

Interfaz gráfica simple con Tkinter.

Keywords, dominios y webhook configurables desde la UI.

🛠️ Requisitos
Python 3.11+

Paquetes de dependencia previos antes de instalar:

Code
pip install google-auth google-auth-oauthlib google-api-python-client requests
Archivo client_secret.json descargado desde su Google Cloud Console usando su Gmail.

Permisos habilitados para Gmail API.

📥 Instalación
Clonar o descomprimir el proyecto.

Colocar client_secret.json en la misma carpeta del script.

Instalar dependencias:

Code
pip install -r requirements.txt
(Opcional: puedes generar este archivo con tus dependencias)

▶️ Ejecución

Code
python scanner.py
La primera vez se abrirá una ventana del navegador para autorizar el acceso a Gmail.
Después se generará automáticamente token.json.

🧪 Uso de la aplicación

1. Configurar Webhook
Escribir la URL en el campo correspondiente.

Presionar Guardar webhook.

También puedes restaurar el webhook por defecto.

2. Añadir palabras clave
Escribir una o varias separadas por coma:

Code
confidencial, contraseña, urgente
3. Añadir dominios a whitelist
Ejemplo:

Code
suempresa.com
google.com

4. Iniciar monitoreo
Presionar INICIAR MONITOREO.

La app revisará los últimos correos y mostrará:

✔️ si el correo está limpio

❌ si contiene amenazas

5. Alertas
Las alertas se guardan en:

alertas.txt
Y opcionalmente se envían al Webhook configurado.

📄 Estructura del proyecto
Code
/proyecto
│── scanner.py
│── client_secret.json
│── token.json (se genera automáticamente)
│── alertas.txt
│── README.md

🧩 Notas adicionales
Puedes usar una cuenta Gmail de pruebas para evitar riesgos.

El token OAuth se renueva automáticamente.

El análisis se hace sobre los últimos 10 correos (puedes modificarlo).

📜 Licencia
Uso libre para fines educativos o empresariales internos.



👤 Autor
Daniel Enrique Herrera Ferrer

Especialista IT 

https://www.linkedin.com/in/daniel-herrera-it-specialist/


