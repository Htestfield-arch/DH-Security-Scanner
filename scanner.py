import os
import base64
import requests
import tkinter as tk
from tkinter import scrolledtext
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Rutas base y archivos necesarios
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    BASE_DIR = os.getcwd()

FILE_CLIENT_SECRET = os.path.join(BASE_DIR, "client_secret.json")
FILE_TOKEN = os.path.join(BASE_DIR, "token.json")
FILE_ALERTS = os.path.join(BASE_DIR, "alertas.txt")

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


class GmailSecurityScanner:
    def __init__(self, root):
        # Configuración de ventana principal
        self.root = root
        self.root.title("BuscadorDH - Gmail Security Scanner")
        self.root.geometry("760x780")

        # Variables internas
        self.running = False
        self.keywords = ["confidencial", "contraseña"]  # Palabras clave iniciales
        self.whitelist_domains = ["google.com"]         # Dominios seguros
        self.forbidden_ext = {".zip", ".exe", ".bat", ".js"}  # Adjuntos peligrosos

        # Webhook por defecto
        self.webhook_url = "https://miwebhook.com/alerta"

        self.setup_ui()

    def setup_ui(self):
        # Título
        tk.Label(self.root, text="Gmail Scanner & Webhook Alert",
                 font=("Arial", 14, "bold")).pack(pady=10)

        # ---------------- WEBHOOK ----------------
        frame_webhook = tk.LabelFrame(self.root, text="Webhook", padx=10, pady=10)
        frame_webhook.pack(pady=5, fill="x", padx=20)

        self.entry_webhook = tk.Entry(frame_webhook, width=60)
        self.entry_webhook.grid(row=0, column=0, padx=5, pady=3)

        tk.Button(frame_webhook, text="Guardar webhook",
                  command=self.set_webhook).grid(row=0, column=1, padx=5)

        tk.Button(frame_webhook, text="Restaurar webhook",
                  command=self.restore_webhook).grid(row=0, column=2, padx=5)

        self.lbl_webhook = tk.Label(
            frame_webhook,
            text=f"Webhook: {self.webhook_url}",
            fg="purple",
            wraplength=680
        )
        self.lbl_webhook.grid(row=1, column=0, columnspan=3, pady=5)

        # ---------------- KEYWORDS ----------------
        frame_keywords = tk.LabelFrame(self.root, text="Keywords", padx=10, pady=10)
        frame_keywords.pack(pady=5, fill="x", padx=20)

        self.entry_kw = tk.Entry(frame_keywords, width=30)
        self.entry_kw.grid(row=0, column=0, padx=5, pady=3)

        tk.Button(frame_keywords, text="Añadir keyword(s)",
                  command=self.add_keyword).grid(row=0, column=1, padx=5)

        self.lbl_kw = tk.Label(
            frame_keywords,
            text=f"Buscando: {', '.join(self.keywords)}",
            fg="blue",
            wraplength=680
        )
        self.lbl_kw.grid(row=1, column=0, columnspan=2, pady=5)

        # ---------------- WHITELIST ----------------
        frame_white = tk.LabelFrame(self.root, text="Whitelist por Dominio", padx=10, pady=10)
        frame_white.pack(pady=5, fill="x", padx=20)

        self.entry_dom = tk.Entry(frame_white, width=30)
        self.entry_dom.grid(row=0, column=0, padx=5, pady=3)

        tk.Button(frame_white, text="Añadir dominio",
                  command=self.add_domain).grid(row=0, column=1, padx=5)

        self.lbl_white = tk.Label(
            frame_white,
            text=f"Ignorando: {', '.join(self.whitelist_domains)}",
            fg="green",
            wraplength=680
        )
        self.lbl_white.grid(row=1, column=0, columnspan=2, pady=5)

        # ---------------- BOTONES ----------------
        self.btn_run = tk.Button(
            self.root,
            text="INICIAR MONITOREO",
            command=self.start_scan,
            bg="#28a745",
            fg="white",
            font=("Arial", 10, "bold")
        )
        self.btn_run.pack(pady=10, fill="x", padx=100)

        self.btn_stop = tk.Button(
            self.root,
            text="DETENER Y SALIR",
            command=self.stop_scan,
            bg="#dc3545",
            fg="white"
        )
        self.btn_stop.pack(pady=5)

        # ---------------- LOG ----------------
        self.log_widget = scrolledtext.ScrolledText(
            self.root,
            height=24,
            width=88,
            bg="#f8f9fa",
            font=("Consolas", 10)
        )
        self.log_widget.pack(pady=10, padx=10)

    def log(self, msg):
        """Escribe mensajes en el panel de log."""
        self.log_widget.insert(tk.END, f"{msg}\n")
        self.log_widget.see(tk.END)

    # ---------------- WEBHOOK ----------------
    def set_webhook(self):
        """Guarda un webhook personalizado."""
        url = self.entry_webhook.get().strip()
        if url:
            self.webhook_url = url
            self.lbl_webhook.config(text=f"Webhook: {self.webhook_url}")
            self.entry_webhook.delete(0, tk.END)

    def restore_webhook(self):
        """Restaura el webhook por defecto."""
        self.webhook_url = "https://miwebhook.com/alerta"
        self.lbl_webhook.config(text=f"Webhook restaurado: {self.webhook_url}")

    # ---------------- KEYWORDS ----------------
    def add_keyword(self):
        """Añade una o varias keywords separadas por coma."""
        kw = self.entry_kw.get().strip().lower()
        if not kw:
            return

        if "," in kw:
            nuevos = [k.strip() for k in kw.split(",") if k.strip()]
            for k in nuevos:
                if k not in self.keywords:
                    self.keywords.append(k)
        else:
            if kw not in self.keywords:
                self.keywords.append(kw)

        self.lbl_kw.config(text=f"Buscando: {', '.join(self.keywords)}")
        self.entry_kw.delete(0, tk.END)

    # ---------------- WHITELIST ----------------
    def add_domain(self):
        """Añade un dominio seguro a la whitelist."""
        dom = self.entry_dom.get().strip().lower().lstrip("@")
        if dom and dom not in self.whitelist_domains:
            self.whitelist_domains.append(dom)
            self.lbl_white.config(text=f"Ignorando: {', '.join(self.whitelist_domains)}")
            self.entry_dom.delete(0, tk.END)

    # ---------------- WEBHOOK ALERTA ----------------
    def send_webhook(self, data):
        """Envía una alerta al webhook configurado."""
        if not self.webhook_url:
            self.log("> ⚠️ Webhook no configurado.")
            return

        try:
            response = requests.post(self.webhook_url, json=data, timeout=5)
            if 200 <= response.status_code < 300:
                self.log(f"> 🚀 Webhook OK: {response.status_code}")
            else:
                self.log(f"> ⚠️ Webhook respondió con estado: {response.status_code}")
        except Exception as e:
            self.log(f"> ❌ Webhook error: {e}")

    # ---------------- GMAIL API ----------------
    def get_gmail_service(self):
        """Autentica y devuelve el servicio Gmail API."""
        creds = None

        if os.path.exists(FILE_TOKEN):
            creds = Credentials.from_authorized_user_file(FILE_TOKEN, SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(FILE_CLIENT_SECRET, SCOPES)
                creds = flow.run_local_server(port=0)

            with open(FILE_TOKEN, "w", encoding="utf-8") as token:
                token.write(creds.to_json())

        return build("gmail", "v1", credentials=creds)

    def get_header(self, headers, name, default=""):
        """Obtiene un header específico del correo."""
        return next((h.get("value", default)
                     for h in headers
                     if h.get("name", "").lower() == name.lower()), default)

    def get_email_address(self, sender):
        """Extrae el correo electrónico del campo From."""
        if "<" in sender and ">" in sender:
            return sender.split("<", 1)[1].split(">", 1)[0].strip().lower()
        return sender.strip().lower()

    def extract_body_from_payload(self, payload):
        """Extrae el texto del cuerpo del correo."""
        parts = payload.get("parts", [payload])
        body_text = []
        stack = parts[:]

        while stack:
            part = stack.pop()
            mime_type = part.get("mimeType", "")
            data = part.get("body", {}).get("data")

            if mime_type.startswith("text/") and data:
                try:
                    decoded = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
                    body_text.append(decoded)
                except:
                    pass

            stack.extend(part.get("parts", []))

        return "\n".join(body_text)

    def find_attachments(self, payload):
        """Busca adjuntos peligrosos en el correo."""
        found = []
        stack = [payload]

        while stack:
            part = stack.pop()
            filename = part.get("filename", "")
            attachment_id = part.get("body", {}).get("attachmentId")

            if filename and attachment_id:
                ext = os.path.splitext(filename.lower())[1]
                if ext in self.forbidden_ext:
                    found.append(filename)

            stack.extend(part.get("parts", []))

        return found

    # ---------------- SCAN ----------------
    def scan(self):
        """Escanea los últimos correos en busca de amenazas."""
        try:
            service = self.get_gmail_service()
            self.log("> Conexión establecida. Revisando últimos correos...")

            results = service.users().messages().list(userId="me", maxResults=10).execute()
            messages = results.get("messages", [])

            for m_info in messages:
                if not self.running:
                    break

                msg = service.users().messages().get(
                    userId="me",
                    id=m_info["id"],
                    format="full"
                ).execute()

                payload = msg.get("payload", {})
                headers = payload.get("headers", [])

                subject = self.get_header(headers, "Subject", "Sin Asunto")
                sender = self.get_header(headers, "From", "Desconocido")
                sender_email = self.get_email_address(sender)

                # Saltar correos de dominios seguros
                if any(sender_email.endswith(f"@{dom}") or sender_email == dom
                       for dom in self.whitelist_domains):
                    continue

                body = self.extract_body_from_payload(payload)
                subject_l = subject.lower()
                body_l = body.lower()

                found_keywords = [k for k in self.keywords if k in subject_l or k in body_l]
                attachments = self.find_attachments(payload)

                # ---------------- ALERTA VISUAL ----------------
                if found_keywords or attachments:
                    self.log("\n" + "=" * 60)
                    self.log("🚨 ¡ALERTA DE SEGURIDAD DETECTADA!")
                    self.log(f"📩 REMITENTE: {sender}")
                    self.log(f"📌 ASUNTO   : {subject}")

                    if found_keywords:
                        self.log(f"🎯 PALABRA(S): {', '.join(found_keywords)}")

                    if attachments:
                        self.log(f"📎 ADJUNTOS  : {', '.join(attachments)}")

                    self.log("❌ Amenaza detectada en este correo.")
                    self.log("=" * 60)

                    # Guardar en archivo
                    with open(FILE_ALERTS, "a", encoding="utf-8") as f:
                        f.write(
                            f"From: {sender} | Subject: {subject} | "
                            f"Keywords: {found_keywords} | Attachments: {attachments}\n"
                        )

                    # Enviar webhook
                    self.send_webhook({
                        "event": "Security Match",
                        "from": sender,
                        "subject": subject,
                        "keywords": found_keywords,
                        "attachments": attachments,
                    })

                else:
                    self.log(f"✔️ Correo limpio: {subject}")

            self.log("\n> Escaneo finalizado con éxito.")

        except Exception as e:
            self.log(f"\n> ERROR CRÍTICO: {e}")
        finally:
            self.running = False

    def start_scan(self):
        """Inicia el escaneo."""
        self.running = True
        self.scan()

    def stop_scan(self):
        """Detiene el escaneo y cierra la app."""
        self.running = False
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = GmailSecurityScanner(root)
    root.mainloop()
