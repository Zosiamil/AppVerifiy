import os
import hashlib
import requests
import json
import math
import threading
import subprocess
from collections import Counter
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import filedialog

# ====== KONFIGURACJA ======
VT_API_KEY = os.environ.get("VT_API_KEY")
MB_API_KEY = os.environ.get("MB_API_KEY")
HA_API_KEY = os.environ.get("HA_API_KEY")
OTX_API_KEY = os.environ.get("OTX_API_KEY")


# ====== FUNKCJE POMOCNICZE (LOGI) ======

def run_powershell_search(log_name, file_name):
    """
    Odpala PowerShella i szuka nazwy pliku w ostatnich 2000 zdarzeniach.
    """

    ps_command = f"""
    Get-WinEvent -LogName '{log_name}' -ErrorAction SilentlyContinue -MaxEvents 2000 | 
    Where-Object {{ $_.Message -like '*{file_name}*' }} | 
    Select-Object -First 3 TimeCreated, Id, Message | 
    Format-List
    """

    try:

        startup_info = subprocess.STARTUPINFO()
        startup_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        process = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True,
            text=True,
            startupinfo=startup_info,
            encoding='oem'
        )
        return process.stdout.strip()
    except Exception as e:
        return f"Błąd skryptu: {str(e)}"


def check_event_logs(file_path):
    file_name = os.path.basename(file_path)
    log_report = []

    log_report.append(f"\n--- [SYSTEM] EVENT LOGS (Szukam: {file_name}) ---")

    # 1. WINDOWS DEFENDER
    defender = run_powershell_search("Microsoft-Windows-Windows Defender/Operational", file_name)
    if defender:
        log_report.append(f"\n[!] DEFENDER ZNALAZŁ ŚLADY:\n{defender}")
    else:
        log_report.append("\n[+] Defender: Czysto w ostatnich logach.")

    # 2. SECURITY (Wymaga Admina)
    try:
        security = run_powershell_search("Security", file_name)
        if security:
            log_report.append(f"\n[!] SECURITY LOG (Uruchomienia):\n{security}")
        else:
            log_report.append("\n[+] Security: Brak śladów uruchomienia (lub brak audytu/admina).")
    except:
        log_report.append("\n[?] Security: Brak dostępu.")

    # 3. APPLICATION (Crashes)
    app = run_powershell_search("Application", file_name)
    if app:
        log_report.append(f"\n[!] APPLICATION ERROR (Crashes):\n{app}")
    else:
        log_report.append("\n[+] Application: Brak błędów aplikacji.")

    return "\n".join(log_report)


# ====== FUNKCJE ANALITYCZNE ======

def calc_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(block)
    return sha256_hash.hexdigest()


def vt_lookup(sha256):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VT_API_KEY}
        )
        if r.status_code == 200:
            data = r.json()
            return data["data"]["attributes"]["last_analysis_stats"]
    except:
        return None
    return None


def mb_lookup(sha256):
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"Auth-Key": MB_API_KEY},
            data={"query": "get_info", "hash": sha256},
            timeout=10
        )
        data = r.json()
        if data.get("query_status") == "ok":
            return data["data"]
    except:
        return None
    return None


def ha_lookup(sha256):
    try:
        r = requests.get(
            f"https://hybrid-analysis.com/api/v2/search/hash?hash={sha256}",
            headers={"api-key": HA_API_KEY, "User-Agent": "Falcon"},
        )
        if r.status_code == 200:
            data = r.json()
            return data
    except:
        return None
    return None


def otx_lookup(sha256):
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY}
        )
        if r.status_code == 200:
            data = r.json()
            return data
    except:
        return None
    return None


def calc_entropy(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    if not data: return 0.0
    counter = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def analyze_file(file_path):
    output = []
    if not os.path.exists(file_path):
        return "[ERROR] Plik nie istnieje"

    output.append("[INFO] Analizowany plik:")
    output.append(file_path)

    # 1. Sprawdzamy logi systemowe
    logs_result = check_event_logs(file_path)
    output.append(logs_result)

    sha256 = calc_sha256(file_path)
    output.append(f"\n[SHA256]\n{sha256}")

    # Wykonaj zapytania (wątek to obsłuży)
    vt = vt_lookup(sha256)
    if vt:
        output.append("\n[VirusTotal]")
        output.append(json.dumps(vt, indent=2))
    else:
        output.append("\n[VirusTotal] Brak w bazie / Błąd")

    mb = mb_lookup(sha256)
    if mb:
        output.append("\n[MalwareBazaar]")
        output.append(json.dumps(mb, indent=2))
    else:
        output.append("\n[MalwareBazaar] Brak w bazie")

    ha = ha_lookup(sha256)
    if ha:
        output.append("\n[HybridAnalisys]")
        output.append(json.dumps(ha, indent=2))
    else:
        output.append("\n[HybridAnalisys] Brak w bazie / Błąd")

    otx = otx_lookup(sha256)
    if otx:
        output.append("\n[AlienVault OTX]")
        output.append(json.dumps(otx, indent=2))
    else:
        output.append("\n[AlienVault] Brak w bazie / Błąd")

    entropy = calc_entropy(file_path)
    output.append(f"\n[ENTROPIA]\n{entropy}")

    if entropy > 7.7:
        output.append("WYSOKA - możliwe pakowanie")
    elif entropy > 6.5:
        output.append("ŚREDNIA - plik binarny")
    else:
        output.append("NISKA - plik tekstowy")

    return "\n".join(output)


# ====== GUI ======

def run_gui():
    window = tk.Tk()
    window.title("Analiza bezpieczeństwa pliku")
    window.geometry("900x900")

    selected_file = {"path": None}

    text_area = ScrolledText(window, wrap=tk.WORD, state='disabled', cursor="arrow")
    text_area.pack(expand=True, fill="both", padx=10, pady=10)

    # --- FUNKCJE POMOCNICZA DO WPISYWANIA TEKSTU ---
    def set_text(content):
        text_area.config(state='normal')
        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, content)
        text_area.config(state='disabled')

        # --- FUNKCJE WĄTKÓW ---

    def update_gui_result(result_text):
        """Ta funkcja wykonuje się bezpiecznie w wątku głównym"""

        set_text(result_text)
        btn_analyze.config(state="normal")

    def worker_thread(path):
        """To jest ciało wątku"""
        wynik = analyze_file(path)
        window.after(0, update_gui_result, wynik)

    def on_analyze_click():
        if not selected_file["path"]:
            set_text("\n[ERROR] Nie wybrano pliku")
            return

        btn_analyze.config(state="disabled")
        set_text(
            "[INFO] Proszę czekać...\n1. Przeszukuję Event Logi (Security, Defender)...\n2. Odpytuję bazy wirusów...")

        t = threading.Thread(target=worker_thread, args=(selected_file["path"],))
        t.start()

    # --- RESZTA GUI ---

    def choose_file():
        path = filedialog.askopenfilename()
        if path:
            selected_file["path"] = path
            set_text(f"[INFO] Wybrany plik:\n{path}")

    button_frame = tk.Frame(window)
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Wybierz plik", command=choose_file).pack(side=tk.LEFT, padx=5)

    global btn_analyze
    btn_analyze = tk.Button(button_frame, text="Analizuj", command=on_analyze_click)
    btn_analyze.pack(side=tk.LEFT, padx=5)

    window.mainloop()


run_gui()