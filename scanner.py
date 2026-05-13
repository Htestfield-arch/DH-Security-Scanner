import os
import base64
import requests
import tkinter as tk
from tkinter import messagebox, scrolledtext
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# --- CONFIGURACIÓN DE ARCHIVOS ---
try:
    # Si se ejecuta como script normal
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    # Si se ejecuta en entornos interactivos raros
    BASE_DIR = os.getcwd()

FILE_CLIENT_SECRET = os.path.join(BASE_DIR, 'client_secret.json')
FILE_TOKEN = os.path.join(BASE_DIR, 'token.json')
FILE_ALERTS = os.path.join(BASE_DIR, 'alertas.txt')

# URL del Webhook (Reemplazar con una propia o configurar vía interfaz)
URL_WEBHOOK = "https://webhook.site/2f2066c1-349d-4a19-9446-93a041e38377" 

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class GmailSecurityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("BuscadorDH - Gmail Security Scanner")
        self.root.geometry("600x650")
        
        self.running = False
        self.keywords = ["confidencial", "contraseña", "clave", "password"]
        self.whitelist = ["@google.com"]
        self.forbidden_ext = [".zip", ".exe", ".bat", ".js"]

        self.setup_ui()

    def setup_ui(self):
        # Título
        tk.Label(self.root, text="Gmail Scanner & Webhook Alert", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Buscador Dinámico
        frame_search = tk.LabelFrame(self.root, text="Gestión de Palabras Clave", padx=10, pady=10)
        frame_search.pack(pady=5, fill="x", padx=20)
        
        self.entry_kw = tk.Entry(frame_search, width=30)
        self.entry_kw.grid(row=0, column=0, padx=5)
        tk.Button(frame_search, text="Añadir", command=self.add_keyword).grid(row=0, column=1)
        
        self.lbl_kw = tk.Label(frame_search, text=f"Buscando: {', '.join(self.keywords)}", fg="blue", wraplength=500)
        self.lbl_kw.grid(row=1, column=0, columnspan=2, pady=5)

        # Botones de Acción
        self.btn_run = tk.Button(self.root, text="INICIAR MONITOREO", command=self.start_scan, bg="#28a745", fg="white", font=("Arial", 10, "bold"))
        self.btn_run.pack(pady=10, fill="x", padx=100)

        self.btn_stop = tk.Button(self.root, text="DETENER Y SALIR", command=self.stop_scan, bg="#dc3545", fg="white")
        self.btn_stop.pack(pady=5)

        # Log de Actividad
        self.log_widget = scrolledtext.ScrolledText(self.root, height=15, width=70, bg="#f8f9fa")
        self.log_widget.pack(pady=10, padx=10)

    def log(self, msg):
        self.log_widget.insert(tk.END, f"> {msg}\n")
        self.log_widget.see(tk.END)

    def add_keyword(self):
        kw = self.entry_kw.get().strip().lower()
        if kw and kw not in self.keywords:
            self.keywords.append(kw)
            self.lbl_kw.config(text=f"Buscando: {', '.join(self.keywords)}")
            self.entry_kw.delete(0, tk.END)

    def send_webhook(self, data):
        try:
            requests.post(URL_WEBHOOK, json=data, timeout=5)
            self.log("🚀 Notificación enviada vía Webhook.")
        except:
            self.log("⚠️ Error al conectar con el Webhook.")

    def get_gmail_service(self):
        creds = None
        if os.path.exists(FILE_TOKEN):
            creds = Credentials.from_authorized_user_file(FILE_TOKEN, SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists(FILE_CLIENT_SECRET):
                    raise FileNotFoundError(f"No se encontró {FILE_CLIENT_SECRET}")
                flow = InstalledAppFlow.from_client_secrets_file(FILE_CLIENT_SECRET, SCOPES)
                creds = flow.run_local_server(port=0)
            with open(FILE_TOKEN, 'w') as token:
                token.write(creds.to_json())
        return build('gmail', 'v1', credentials=creds)

    def scan(self):
        try:
            service = self.get_gmail_service()
            self.log("Conexión establecida. Revisando últimos correos...")
            
            results = service.users().messages().list(userId='me', maxResults=10).execute()
            messages = results.get('messages', [])

            for m_info in messages:
                if not self.running: break
                msg = service.users().messages().get(userId='me', id=m_info['id']).execute()
                headers = msg['payload']['headers']
                
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "S/A")
                sender = next((h['value'] for h in headers if h['name'] == 'From'), "Unknown")

                if any(white in sender for white in self.whitelist): continue

                # Detección
                found = [k for k in self.keywords if k in subject.lower()]
                if found:
                    self.log(f"❗ ALERTA: '{subject}' detectado.")
                    alert_data = {"event": "Security Match", "from": sender, "subject": subject, "match": found}
                    
                    with open(FILE_ALERTS, "a", encoding="utf-8") as f:
                        f.write(f"Match: {found} | From: {sender} | Sub: {subject}\n")
                    
                    self.send_webhook(alert_data)

            self.log("Escaneo finalizado con éxito.")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.running = False

    def start_scan(self):
        self.running = True
        self.scan()

    def stop_scan(self):
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = GmailSecurityScanner(root)
    root.mainloop()
