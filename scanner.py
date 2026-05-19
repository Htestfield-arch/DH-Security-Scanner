import os
import json
import base64
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    BASE_DIR = os.getcwd()

FILE_CLIENT_SECRET = os.path.join(BASE_DIR, "client_secret.json")
FILE_TOKEN = os.path.join(BASE_DIR, "token.json")
FILE_ALERTS = os.path.join(BASE_DIR, "alertas.txt")
FILE_CONFIG = os.path.join(BASE_DIR, "config.json")

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

DEFAULT_CONFIG = {
    "webhook_url": "https://miwebhook.com/alerta",
    "keywords": ["confidencial", "contraseña", "contrasena"],
    "whitelist_domains": ["google.com"],
    "forbidden_ext": [".zip", ".exe", ".bat", ".js"],
    "dark_mode": True
}


class GmailSecurityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("BuscadorDH - Gmail Security Scanner")
        self.root.geometry("820x860")
        self.root.minsize(820, 860)

        self.running = False
        self.scan_thread = None
        self.ui_lock = threading.Lock()

        self.config = self.load_config()
        self.webhook_url = self.config.get("webhook_url", DEFAULT_CONFIG["webhook_url"])
        self.keywords = list(self.config.get("keywords", DEFAULT_CONFIG["keywords"]))
        self.whitelist_domains = list(self.config.get("whitelist_domains", DEFAULT_CONFIG["whitelist_domains"]))
        self.forbidden_ext = set(self.config.get("forbidden_ext", DEFAULT_CONFIG["forbidden_ext"]))
        self.dark_mode = bool(self.config.get("dark_mode", DEFAULT_CONFIG["dark_mode"]))

        self.font_title = ("Inter", 14, "bold")
        self.font_body = ("Inter", 10)
        self.font_body_bold = ("Inter", 10, "bold")
        self.font_mono = ("Consolas", 10)

        self.bg_dark = "#101010"
        self.bg_panel = "#1A1A1A"
        self.bg_card = "#171717"
        self.fg_light = "#F2F2F2"
        self.fg_muted = "#C7C7C7"
        self.accent = "#FF675B"
        self.accent_soft = "#FF8A80"
        self.ok = "#28a745"
        self.warning = "#f0ad4e"
        self.danger = "#dc3545"

        self.setup_ui()
        self.apply_theme()
        self.refresh_labels()
        self.log("> Aplicación cargada correctamente.")

    def load_config(self):
        if os.path.exists(FILE_CONFIG):
            try:
                with open(FILE_CONFIG, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            except Exception:
                pass
        self.save_config(DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)

    def save_config(self, data=None):
        payload = data if data is not None else {
            "webhook_url": self.webhook_url,
            "keywords": self.keywords,
            "whitelist_domains": self.whitelist_domains,
            "forbidden_ext": sorted(self.forbidden_ext),
            "dark_mode": self.dark_mode
        }
        try:
            with open(FILE_CONFIG, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.log(f"> ERROR guardando config: {e}")

    def setup_ui(self):
        self.root.configure(bg=self.bg_dark if self.dark_mode else "#EDEDED")

        self.title_label = tk.Label(self.root, text="Gmail Scanner & Webhook Alert", font=self.font_title)
        self.title_label.pack(pady=10)

        frame_webhook = tk.LabelFrame(self.root, text="Webhook", padx=10, pady=10)
        frame_webhook.pack(pady=5, fill="x", padx=20)
        self.frame_webhook = frame_webhook

        self.entry_webhook = tk.Entry(frame_webhook, width=60, font=self.font_body)
        self.entry_webhook.grid(row=0, column=0, padx=5, pady=3, sticky="we")
        tk.Button(frame_webhook, text="Guardar webhook", command=self.set_webhook).grid(row=0, column=1, padx=5)
        tk.Button(frame_webhook, text="Restaurar webhook", command=self.restore_webhook).grid(row=0, column=2, padx=5)

        self.lbl_webhook = tk.Label(frame_webhook, text=f"Webhook: {self.webhook_url}", wraplength=720, justify="left")
        self.lbl_webhook.grid(row=1, column=0, columnspan=3, pady=5, sticky="w")

        frame_keywords = tk.LabelFrame(self.root, text="Keywords", padx=10, pady=10)
        frame_keywords.pack(pady=5, fill="x", padx=20)
        self.frame_keywords = frame_keywords

        self.entry_kw = tk.Entry(frame_keywords, width=30, font=self.font_body)
        self.entry_kw.grid(row=0, column=0, padx=5, pady=3, sticky="we")
        tk.Button(frame_keywords, text="Añadir keyword(s)", command=self.add_keyword).grid(row=0, column=1, padx=5)

        self.lbl_kw = tk.Label(frame_keywords, wraplength=720, justify="left")
        self.lbl_kw.grid(row=1, column=0, columnspan=2, pady=5, sticky="w")

        frame_white = tk.LabelFrame(self.root, text="Whitelist por Dominio", padx=10, pady=10)
        frame_white.pack(pady=5, fill="x", padx=20)
        self.frame_white = frame_white

        self.entry_dom = tk.Entry(frame_white, width=30, font=self.font_body)
        self.entry_dom.grid(row=0, column=0, padx=5, pady=3, sticky="we")
        tk.Button(frame_white, text="Añadir dominio", command=self.add_domain).grid(row=0, column=1, padx=5)

        self.lbl_white = tk.Label(frame_white, wraplength=720, justify="left")
        self.lbl_white.grid(row=1, column=0, columnspan=2, pady=5, sticky="w")

        frame_ext = tk.LabelFrame(self.root, text="Extensiones peligrosas", padx=10, pady=10)
        frame_ext.pack(pady=5, fill="x", padx=20)
        self.frame_ext = frame_ext

        self.entry_ext = tk.Entry(frame_ext, width=30, font=self.font_body)
        self.entry_ext.grid(row=0, column=0, padx=5, pady=3, sticky="we")
        tk.Button(frame_ext, text="Añadir extensión", command=self.add_extension).grid(row=0, column=1, padx=5)
        tk.Button(frame_ext, text="Guardar cambios", command=self.persist_settings).grid(row=0, column=2, padx=5)

        self.lbl_ext = tk.Label(frame_ext, wraplength=720, justify="left")
        self.lbl_ext.grid(row=1, column=0, columnspan=3, pady=5, sticky="w")

        frame_theme = tk.Frame(self.root)
        frame_theme.pack(pady=5, fill="x", padx=20)
        self.chk_dark_var = tk.BooleanVar(value=self.dark_mode)
        self.chk_dark = tk.Checkbutton(frame_theme, text="Tema oscuro", variable=self.chk_dark_var, command=self.toggle_theme)
        self.chk_dark.pack(anchor="w")

        frame_buttons = tk.Frame(self.root)
        frame_buttons.pack(pady=10, fill="x", padx=100)
        self.frame_buttons = frame_buttons

        self.btn_run = tk.Button(frame_buttons, text="INICIAR MONITOREO", command=self.start_scan, bg=self.ok, fg="white", font=self.font_body_bold)
        self.btn_run.grid(row=0, column=0, padx=5, sticky="we")
        self.btn_stop = tk.Button(frame_buttons, text="DETENER", command=self.stop_scan, bg=self.warning, fg="white", font=self.font_body_bold)
        self.btn_stop.grid(row=0, column=1, padx=5, sticky="we")
        self.btn_exit = tk.Button(frame_buttons, text="SALIR", command=self.exit_app, bg=self.danger, fg="white", font=self.font_body_bold)
        self.btn_exit.grid(row=0, column=2, padx=5, sticky="we")

        frame_buttons.columnconfigure(0, weight=1)
        frame_buttons.columnconfigure(1, weight=1)
        frame_buttons.columnconfigure(2, weight=1)

        self.log_widget = scrolledtext.ScrolledText(self.root, height=26, width=88, bg="#ffffff", font=self.font_mono, wrap=tk.WORD)
        self.log_widget.pack(pady=10, padx=10, fill="both", expand=True)

    def apply_theme(self):
        bg = self.bg_dark if self.dark_mode else "#EDEDED"
        panel = self.bg_panel if self.dark_mode else "#FFFFFF"
        card = self.bg_card if self.dark_mode else "#FFFFFF"
        fg = self.fg_light if self.dark_mode else "#111111"
        muted = self.fg_muted if self.dark_mode else "#333333"

        self.root.configure(bg=bg)
        widgets = [self.title_label, self.lbl_webhook, self.lbl_kw, self.lbl_white, self.lbl_ext, self.chk_dark]
        for w in widgets:
            try:
                w.config(bg=bg, fg=fg)
            except Exception:
                pass

        for frame in [self.frame_webhook, self.frame_keywords, self.frame_white, self.frame_ext, self.frame_buttons]:
            try:
                frame.config(bg=panel, fg=fg)
            except Exception:
                pass

        for child in self.root.winfo_children():
            if isinstance(child, tk.LabelFrame) or isinstance(child, tk.Frame):
                try:
                    child.config(bg=panel)
                except Exception:
                    pass
                for sub in child.winfo_children():
                    try:
                        if isinstance(sub, (tk.Label, tk.Checkbutton)):
                            sub.config(bg=panel if not isinstance(child, tk.Frame) else bg, fg=fg)
                        elif isinstance(sub, tk.Entry):
                            sub.config(bg=card if self.dark_mode else "#FFFFFF", fg=fg, insertbackground=fg)
                        elif isinstance(sub, tk.Button):
                            sub.config(activebackground=self.accent_soft)
                    except Exception:
                        pass

        try:
            self.log_widget.config(bg=card, fg=fg, insertbackground=fg, highlightbackground=muted)
        except Exception:
            pass

        self.refresh_labels()

    def toggle_theme(self):
        self.dark_mode = bool(self.chk_dark_var.get())
        self.apply_theme()
        self.persist_settings()

    def refresh_labels(self):
        self.lbl_webhook.config(text=f"Webhook: {self.webhook_url}")
        self.lbl_kw.config(text=f"Buscando: {', '.join(self.keywords)}")
        self.lbl_white.config(text=f"Ignorando: {', '.join(self.whitelist_domains)}")
        self.lbl_ext.config(text=f"Extensiones: {', '.join(sorted(self.forbidden_ext))}")

    def persist_settings(self):
        self.config = {
            "webhook_url": self.webhook_url,
            "keywords": self.keywords,
            "whitelist_domains": self.whitelist_domains,
            "forbidden_ext": sorted(self.forbidden_ext),
            "dark_mode": self.dark_mode
        }
        self.save_config(self.config)
        self.log("> Configuración guardada en config.json.")

    def log(self, msg):
        with self.ui_lock:
            self.log_widget.configure(state="normal")
            self.log_widget.insert(tk.END, f"{msg}\n")
            self.log_widget.see(tk.END)
            self.log_widget.configure(state="normal")

    def flash_results(self):
        original_bg = self.log_widget.cget("bg")
        self.log_widget.config(bg="#74110A")
        self.root.after(5000, lambda: self.log_widget.config(bg=original_bg))

    def set_webhook(self):
        url = self.entry_webhook.get().strip()
        if url:
            self.webhook_url = url
            self.entry_webhook.delete(0, tk.END)
            self.persist_settings()
            self.refresh_labels()
            self.log("> Webhook actualizado.")

    def restore_webhook(self):
        self.webhook_url = DEFAULT_CONFIG["webhook_url"]
        self.persist_settings()
        self.refresh_labels()
        self.log("> Webhook restaurado al valor por defecto.")

    def add_keyword(self):
        kw = self.entry_kw.get().strip().lower()
        if not kw:
            return
        nuevos = [k.strip() for k in kw.split(",") if k.strip()]
        for k in nuevos:
            if k not in self.keywords:
                self.keywords.append(k)
        self.entry_kw.delete(0, tk.END)
        self.persist_settings()
        self.refresh_labels()
        self.log("> Keywords actualizadas.")

    def add_domain(self):
        dom = self.entry_dom.get().strip().lower().lstrip("@")
        if dom and dom not in self.whitelist_domains:
            self.whitelist_domains.append(dom)
            self.entry_dom.delete(0, tk.END)
            self.persist_settings()
            self.refresh_labels()
            self.log("> Dominio agregado a whitelist.")

    def add_extension(self):
        ext = self.entry_ext.get().strip().lower()
        if not ext:
            return
        ext_list = [e.strip() for e in ext.split(",") if e.strip()]
        added = []
        for item in ext_list:
            normalized = item if item.startswith(".") else f".{item}"
            if normalized not in self.forbidden_ext:
                self.forbidden_ext.add(normalized)
                added.append(normalized)
        self.entry_ext.delete(0, tk.END)
        if added:
            self.persist_settings()
            self.refresh_labels()
            self.log(f"> Extensiones agregadas: {', '.join(added)}")
        else:
            self.log("> No se agregaron nuevas extensiones.")

    def send_webhook(self, data):
        if not self.webhook_url:
            self.log("> ⚠️ Webhook no configurado.")
            return
        try:
            response = requests.post(self.webhook_url, json=data, timeout=5)
            if 200 <= response.status_code < 300:
                self.log(f"> Webhook OK: {response.status_code}")
            else:
                self.log(f"> Webhook respondió con estado: {response.status_code}")
        except Exception as e:
            self.log(f"> Webhook error: {e}")

    def get_gmail_service(self):
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
        return next((h.get("value", default) for h in headers if h.get("name", "").lower() == name.lower()), default)

    def get_email_address(self, sender):
        if "<" in sender and ">" in sender:
            return sender.split("<", 1)[1].split(">", 1)[0].strip().lower()
        return sender.strip().lower()

    def extract_body_from_payload(self, payload):
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
                except Exception:
                    pass
            stack.extend(part.get("parts", []))
        return "\n".join(body_text)

    def find_attachments(self, payload):
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

    def scan(self):
        try:
            service = self.get_gmail_service()
            self.log("> Conexión establecida. Revisando últimos correos...")
            results = service.users().messages().list(userId="me", maxResults=10).execute()
            messages = results.get("messages", [])
            for m_info in messages:
                if not self.running:
                    break
                msg = service.users().messages().get(userId="me", id=m_info["id"], format="full").execute()
                payload = msg.get("payload", {})
                headers = payload.get("headers", [])
                subject = self.get_header(headers, "Subject", "Sin Asunto")
                sender = self.get_header(headers, "From", "Desconocido")
                sender_email = self.get_email_address(sender)

                if any(sender_email.endswith(f"@{dom}") or sender_email == dom for dom in self.whitelist_domains):
                    continue

                body = self.extract_body_from_payload(payload)
                subject_l = subject.lower()
                body_l = body.lower()

                found_keywords = [k for k in self.keywords if k in subject_l or k in body_l]
                attachments = self.find_attachments(payload)

                if found_keywords or attachments:
                    self.log("=" * 60)
                    self.log("🚨 ¡ALERTA DE SEGURIDAD DETECTADA!")
                    self.log(f"📩 REMITENTE: {sender}")
                    self.log(f"📌 ASUNTO: {subject}")
                    if found_keywords:
                        self.log(f"🎯 PALABRA(S): {', '.join(found_keywords)}")
                    if attachments:
                        self.log(f"📎 ADJUNTOS: {', '.join(attachments)}")
                    self.log("❌ Amenaza detectada en este correo.")
                    self.log("=" * 60)

                    self.flash_results()

                    with open(FILE_ALERTS, "a", encoding="utf-8") as f:
                        f.write(
                            f"From: {sender} | Subject: {subject} | "
                            f"Keywords: {found_keywords} | Attachments: {attachments}\n"
                        )

                    self.send_webhook({
                        "event": "Security Match",
                        "from": sender,
                        "subject": subject,
                        "keywords": found_keywords,
                        "attachments": attachments,
                    })
                else:
                    self.log(f"✔️ Correo limpio: {subject}")

            self.log("> Escaneo finalizado con éxito.")
        except Exception as e:
            self.log(f"> ERROR CRÍTICO: {e}")
        finally:
            self.running = False
            self.btn_run.config(state="normal")

    def start_scan(self):
        if self.running:
            return
        self.running = True
        self.btn_run.config(state="disabled")
        self.scan_thread = threading.Thread(target=self.scan, daemon=True)
        self.scan_thread.start()
        self.log("> Escaneo iniciado en segundo plano.")

    def stop_scan(self):
        self.running = False
        self.btn_run.config(state="normal")
        self.log("> Escaneo detenido por el usuario.")

    def exit_app(self):
        self.running = False
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = GmailSecurityScanner(root)
    root.mainloop()
