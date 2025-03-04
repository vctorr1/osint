import customtkinter as ctk
import requests
import hashlib
import re
import csv
import sqlite3
from tkinter import filedialog
from threading import Thread
from bs4 import BeautifulSoup
from urllib.parse import quote

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class AdvancedOSINTTool(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("OSINT Buscador de Credenciales - Víctor Ríos Recio 2025")
        self.geometry("1200x950")
        
        # Configuración de estilos
        self.message_styles = {
            "error": {"icon": "❌", "color": "#FF4444"},
            "warning": {"icon": "⚠️", "color": "#FFB74D"},
            "success": {"icon": "✅", "color": "#81C784"},
            "info": {"icon": "🔍", "color": "#64B5F6"}
        }
        
        self.local_breaches = {"emails": set(), "passwords": set()}
        self.configure_layout()
        self.configure_tags()
        
    def configure_layout(self):
        self.grid_columnconfigure(0, weight=1)
        
        # Cabecera
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=20, pady=10, sticky="ew")
        
        ctk.CTkLabel(header_frame, 
                    text="OSINT Buscador de Credenciales\nCreado por Víctor Ríos Recio - 2025",
                    font=("Arial", 12, "italic")).pack(side="right")
        
        # Sección de configuración
        self.api_frame = ctk.CTkFrame(self)
        self.api_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        self.api_entry = ctk.CTkEntry(self.api_frame, placeholder_text="HIBP API Key (opcional)", width=400)
        self.api_entry.pack(side="left", padx=5)
        
        self.file_btn = ctk.CTkButton(self.api_frame, text="Cargar base local", command=self.load_local_database)
        self.file_btn.pack(side="right", padx=5)
        
        # Campos de entrada
        self.email_entry = ctk.CTkEntry(self, placeholder_text="Correo electrónico")
        self.email_entry.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        
        self.password_entry = ctk.CTkEntry(self, placeholder_text="Contraseña", show="*")
        self.password_entry.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        
        # Botones de acción
        self.btn_frame = ctk.CTkFrame(self)
        self.btn_frame.grid(row=4, column=0, padx=20, pady=10, sticky="ew")
        
        action_buttons = [
            ("Búsqueda completa", lambda: self.start_search(online=True)),
            ("Buscar localmente", lambda: self.start_search(online=False)),
            ("Escanear Pastebin", self.start_pastebin_search)
        ]
        
        for text, command in action_buttons:
            btn = ctk.CTkButton(self.btn_frame, text=text, command=command)
            btn.pack(side="left", padx=5)
        
        # Resultados
        self.results = ctk.CTkTextbox(self, wrap="word", height=500, font=("Consolas", 12), state="disabled")
        self.results.grid(row=5, column=0, padx=20, pady=20, sticky="nsew")
        
    def configure_tags(self):
        for tag, style in self.message_styles.items():
            self.results.tag_config(tag, foreground=style["color"])
        
    def insert_result(self, message, msg_type="info"):
        self.results.configure(state="normal")
        style = self.message_styles.get(msg_type, self.message_styles["info"])
        self.results.insert("end", f"{style['icon']} {message}\n", msg_type)
        self.results.configure(state="disabled")
        self.results.see("end")
        
    def start_pastebin_search(self):
        Thread(target=self.scrape_pastebin, daemon=True).start()
        
    def start_search(self, online):
        Thread(target=lambda: self.full_scan(online), daemon=True).start()
        
    def full_scan(self, online):
        self.clear_results()
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()
        api_key = self.api_entry.get().strip()
        
        try:
            if online:
                if email:
                    self.check_hibp(email, api_key)
                if password:
                    self.check_pwned(password)
            else:
                if email:
                    self.local_email_check(email)
                if password:
                    self.local_password_check(password)
        except Exception as e:
            self.insert_result(f"Error crítico: {str(e)}", "error")

    def clear_results(self):
        self.results.configure(state="normal")
        self.results.delete("1.0", "end")
        self.results.configure(state="disabled")
        
    def load_local_database(self):
        try:
            file_path = filedialog.askopenfilename(filetypes=[
                ("Bases de datos", "*.csv;*.sql;*.txt"),
                ("Todos los archivos", "*.*")
            ])
            
            if file_path:
                if file_path.endswith(".csv"):
                    self.parse_csv(file_path)
                elif file_path.endswith(".sql"):
                    self.parse_sql(file_path)
                elif file_path.endswith(".txt"):
                    self.parse_txt(file_path)
                    
                self.insert_result(f"Base cargada: {file_path}", "success")
        except Exception as e:
            self.insert_result(f"Error cargando archivo: {str(e)}", "error")
            
    def parse_csv(self, path):
        try:
            with open(path, newline="", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if "email" in row:
                        self.local_breaches["emails"].add(row["email"].lower())
                    if "password" in row:
                        self.local_breaches["passwords"].add(hashlib.sha1(row["password"].encode()).hexdigest().lower())
        except Exception as e:
            self.insert_result(f"Error procesando CSV: {str(e)}", "error")
                    
    def parse_sql(self, path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                emails = re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", content, re.I)
                passwords = re.findall(r"(?i)password['\"]?\s*[:=]\s*['\"]([^'\"]+)", content)
                
                self.local_breaches["emails"].update(email.lower() for email in emails)
                self.local_breaches["passwords"].update(hashlib.sha1(pw.encode()).hexdigest().lower() for pw in passwords)
        except Exception as e:
            self.insert_result(f"Error procesando SQL: {str(e)}", "error")
            
    def parse_txt(self, path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if "@" in line and "." in line:
                        self.local_breaches["emails"].add(line.lower())
                    elif line:
                        self.local_breaches["passwords"].add(hashlib.sha1(line.encode()).hexdigest().lower())
        except Exception as e:
            self.insert_result(f"Error procesando TXT: {str(e)}", "error")
    
    def check_hibp(self, email, api_key):
        try:
            headers = {"hibp-api-key": api_key} if api_key else {}
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers=headers,
                params={"truncateResponse": "false"},
                timeout=15
            )
            
            if response.status_code == 200:
                breaches = response.json()
                self.display_hibp_breaches(breaches)
            elif response.status_code == 404:
                self.insert_result("Email no encontrado en fugas conocidas", "success")
            else:
                self.insert_result(f"Error de la API: {response.status_code}", "warning")
                
        except requests.exceptions.RequestException as e:
            self.insert_result(f"Error de conexión: {str(e)}", "error")
        except Exception as e:
            self.insert_result(f"Error inesperado: {str(e)}", "error")
            
    def display_hibp_breaches(self, breaches):
        self.insert_result(f"Se encontraron {len(breaches)} fugas:", "error")
        for breach in breaches:
            details = (
                f"Nombre: {breach['Name']}\n"
                f"Fecha: {breach['BreachDate']}\n"
                f"Datos comprometidos: {', '.join(breach['DataClasses'])}\n"
                f"Dominio: {breach['Domain']}\n"
                "―"*50
            )
            self.insert_result(details, "info")
            
    def check_pwned(self, password):
        try:
            sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"},
                timeout=10
            )
            
            if response.status_code == 200:
                found = False
                for line in response.text.splitlines():
                    if line.startswith(suffix):
                        count = line.split(":")[1]
                        self.insert_result(f"Contraseña comprometida ({count} fugas)", "error")
                        found = True
                        break
                if not found:
                    self.insert_result("Contraseña segura", "success")
            else:
                self.insert_result(f"Error al verificar contraseña: {response.status_code}", "warning")
                
        except requests.exceptions.RequestException as e:
            self.insert_result(f"Error de conexión: {str(e)}", "error")
        except Exception as e:
            self.insert_result(f"Error inesperado: {str(e)}", "error")
            
    def local_email_check(self, email):
        try:
            if email.lower() in self.local_breaches["emails"]:
                self.insert_result("Email encontrado en base local", "error")
            else:
                self.insert_result("Email no encontrado localmente", "success")
        except Exception as e:
            self.insert_result(f"Error en búsqueda local: {str(e)}", "error")
            
    def local_password_check(self, password):
        try:
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().lower()
            if sha1_hash in self.local_breaches["passwords"]:
                self.insert_result("Contraseña encontrada en base local", "error")
            else:
                self.insert_result("Contraseña no encontrada localmente", "success")
        except Exception as e:
            self.insert_result(f"Error en búsqueda local: {str(e)}", "error")
            
    def scrape_pastebin(self):
        try:
            email = self.email_entry.get().strip()
            password = self.password_entry.get().strip()
            
            if not email and not password:
                self.insert_result("Introduce email o contraseña para buscar en Pastebin", "warning")
                return
                
            self.insert_result("Iniciando búsqueda en Pastebin...", "info")
            
            # Construir query de búsqueda
            query_parts = []
            if email:
                query_parts.append(f'"{email}"')
            if password:
                query_parts.append(f'"{password}"')
            
            search_query = " OR ".join(query_parts)
            encoded_query = quote(f'site:pastebin.com {search_query}')
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept-Language": "es-ES,es;q=0.9"
            }
            
            response = requests.get(
                f"https://www.google.com/search?q={encoded_query}",
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                results = soup.select("div.g")
                
                if not results:
                    self.insert_result("No se encontraron resultados públicos", "success")
                    return
                
                self.insert_result("Resultados potenciales en Pastebin:", "info")
                for result in results[:5]:  # Mostrar hasta 5 resultados
                    title = result.select_one("h3").get_text() if result.select_one("h3") else "Sin título"
                    link = result.find("a")["href"] if result.find("a") else "#"
                    snippet = result.select_one(".VwiC3b").get_text() if result.select_one(".VwiC3b") else ""
                    
                    # Resaltar coincidencias
                    if email and email.lower() in snippet.lower():
                        snippet = snippet.replace(email, f'[EMAIL] {email} [/EMAIL]')
                    if password and password in snippet:
                        snippet = snippet.replace(password, f'[PASSWORD] {password} [/PASSWORD]')
                    
                    result_text = (
                        f"🔍 Título: {title}\n"
                        f"🔗 Enlace: {link}\n"
                        f"📄 Fragmento: {snippet[:200]}...\n"
                        "―"*50
                    )
                    self.insert_result(result_text, "info")
            else:
                self.insert_result(f"Error en la búsqueda: {response.status_code}", "warning")
                
        except requests.exceptions.RequestException as e:
            self.insert_result(f"Error de conexión: {str(e)}", "error")
        except Exception as e:
            self.insert_result(f"Error inesperado: {str(e)}", "error")

if __name__ == "__main__":
    app = AdvancedOSINTTool()
    app.mainloop()