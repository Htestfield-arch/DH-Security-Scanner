# DH Security Scanner

Aplicación de escritorio en Python para monitorear correos de Gmail, detectar palabras clave y adjuntos peligrosos, registrar alertas en archivo local y enviar notificaciones por webhook.

## Descripción

DH Security Scanner fue diseñado como una herramienta ligera de análisis y alerta para Gmail usando Python y Tkinter. Permite:

- Configurar un webhook de notificación.
- Agregar keywords personalizadas.
- Definir dominios permitidos.
- Agregar extensiones peligrosas desde la interfaz.
- Registrar alertas en `alertas.txt`.
- Ejecutar el escaneo en segundo plano para no congelar la interfaz.

## Funciones principales

- Escaneo de correos recientes de Gmail.
- Detección de palabras clave en asunto y cuerpo del mensaje.
- Detección de archivos adjuntos por extensión.
- Lista de dominios en whitelist.
- Persistencia de configuración en `config.json`.
- Botones independientes para `DETENER` y `SALIR`.
- Tema oscuro con estilo moderno.
- Resaltado temporal del panel de resultados cuando se detecta una alerta.

## Requisitos

- Python 3.10 o superior.
- Una cuenta de Gmail con acceso autorizado a Gmail API.
- Archivo `client_secret.json` descargado desde Google Cloud Console.
- Conexión a Internet para autenticar Gmail y enviar webhooks.

## Dependencias

Instala las dependencias con:

```bash
pip install -r requirements.txt
```

El archivo `requirements.txt` debe incluir:

```txt
requests
google-auth
google-auth-oauthlib
google-api-python-client
```

## Estructura del proyecto

```text
DH-Security-Scanner/
├─ scanner_reescrito.py
├─ requirements.txt
├─ config.json
├─ client_secret.json
├─ token.json
├─ alertas.txt
└─ README.md
```

## Instalación

### Opción 1: Ejecutar con Python instalado

1. Descarga e instala Python desde:
   https://www.python.org/downloads/

2. Durante la instalación en Windows, activa la opción:
   **Add Python to PATH**

3. Abre una terminal en la carpeta del proyecto.

4. Instala las dependencias:

```bash
pip install -r requirements.txt
```

5. Ejecuta la aplicación:

```bash
python scanner_reescrito.py
```

### Opción 2: Ejecutable para usuarios sin Python

Si deseas distribuir la aplicación sin requerir Python instalado, puedes crear un ejecutable con PyInstaller:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed scanner_reescrito.py
```

El ejecutable quedará en la carpeta `dist/`.

## Configuración de Gmail API

Antes de usar la aplicación, necesitas crear credenciales OAuth:

1. Entra a Google Cloud Console.
2. Crea un proyecto nuevo o usa uno existente.
3. Activa la API de Gmail.
4. Configura la pantalla de consentimiento OAuth.
5. Descarga el archivo `client_secret.json`.
6. Colócalo en la misma carpeta del script.
7. Ejecuta la aplicación por primera vez.
8. Autoriza el acceso a Gmail cuando se abra el navegador.

Después de la primera autenticación, la aplicación generará el archivo `token.json`.

## Uso

1. Ejecuta la aplicación.
2. Configura tu webhook si deseas recibir alertas externas.
3. Agrega keywords relevantes.
4. Agrega dominios seguros a la whitelist.
5. Agrega extensiones peligrosas adicionales si lo necesitas.
6. Presiona **INICIAR MONITOREO**.
7. Usa **DETENER** para pausar el análisis sin cerrar la app.
8. Usa **SALIR** para cerrar la aplicación.

## Persistencia

La aplicación guarda automáticamente la configuración en `config.json`, incluyendo:

- Webhook.
- Keywords.
- Dominios permitidos.
- Extensiones peligrosas.
- Estado del tema oscuro.

## Alertas

Cuando se detecta una coincidencia:

- Se escribe un registro en `alertas.txt`.
- Se envía un webhook si está configurado.
- El panel de resultados cambia temporalmente a color rojo suave.

## Interfaz

La aplicación usa Tkinter con diseño simple y oscuro.  
El fondo principal puede configurarse en `#101010`, y el panel de resultados cambia a `#FF675B` cuando aparece una alerta.

## Instalación rápida en Windows sin conocimientos técnicos

1. Instala Python desde la web oficial.
2. Descarga el proyecto desde GitHub.
3. Copia `client_secret.json` dentro de la carpeta.
4. Abre una consola en la carpeta del proyecto.
5. Ejecuta:

```bash
pip install -r requirements.txt
python scanner_reescrito.py
```

## Compatibilidad

### Windows
Compatible, recomendado para uso con interfaz gráfica.

### Linux
Compatible si tienes entorno gráfico disponible.

### OpenMediaVault con Docker Compose
Es factible, pero la interfaz Tkinter necesita entorno gráfico o acceso remoto.  
Si quieres usarlo en OMV, lo ideal es ejecutar la lógica en modo headless o con escritorio remoto/VNC.

### AWS Lightsail
También es factible, pero se recomienda usarlo como servicio de backend o con entorno gráfico remoto.

## Notas importantes

- El proyecto usa Gmail API, por lo que necesita autorización OAuth.
- El archivo `token.json` se genera automáticamente luego del primer acceso.
- Las extensiones peligrosas pueden ampliarse desde la interfaz.
- La aplicación fue diseñada para ser ligera, funcional y fácil de adaptar.

## Autor

**Daniel Herrera**  
LinkedIn: https://www.linkedin.com/in/daniel-herrera-it-specialist/

## Repositorio

Código fuente:  
https://github.com/Htestfield-arch/DH-Security-Scanner/blob/main/scanner.py

