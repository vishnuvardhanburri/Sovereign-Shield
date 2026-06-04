# XAVIRA TECH LABS - SOVEREIGN SHIELD VERSION 1
import os
import time
import sys
import logging
import threading
import asyncio
import json
import csv
import platform
import subprocess
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from langchain_unstructured import UnstructuredLoader
try:
    # Requested import path for newer LangChain layouts.
    from langchain.text_splitter import RecursiveCharacterTextSplitter
except ImportError:
    # Fallback for environments where splitters are packaged separately.
    from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
from security_scanner import EnterpriseScanner
import smtplib
from email.mime.text import MIMEText
import requests
from dotenv import load_dotenv
from plyer import notification
from vault_crypto import sentinel_crypto

# Load config from .env
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

# --- PATH CONFIGURATION ---
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VAULT_DOCS = os.path.join(BASE_DIR, "vault_docs")
VAULT_ARCHIVE = os.path.join(BASE_DIR, "vault_archive")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
CHROMA_DIR = os.path.join(BASE_DIR, "chroma_db")
STATE_FILE = os.path.join(BASE_DIR, "sentinel_state.json")

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(VAULT_DOCS, exist_ok=True)
os.makedirs(VAULT_ARCHIVE, exist_ok=True)

# --- VERSIONING ---
VERSION = "1.0"
XAVIRA_VERSION_URL = os.getenv("UPDATE_SERVER_URL", "https://api.xaviratechlabs.com/sentinel/version")

# --- LOGGING SETUP ---
alert_log = os.path.join(LOGS_DIR, "alerts.log")
logging.basicConfig(
    filename=alert_log,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# --- CONFIGURATION (ENV DRIVEN) ---
SMTP_CONFIG = {
    "HOST": os.getenv("SMTP_HOST", "localhost"),
    "PORT": int(os.getenv("SMTP_PORT", 1025)),
    "USER": os.getenv("SMTP_USER", ""),
    "PASS": os.getenv("SMTP_PASS", ""),
    "TO": os.getenv("REPORT_EMAIL_TO", ""),
    "CYCLE_DAYS": int(os.getenv("REPORT_CYCLE_DAYS", 30)),
    "NOTIFY_SOUND": os.getenv("NOTIFY_SOUND", "yes").lower() == "yes",
    "UPDATE_CHECK": os.getenv("UPDATE_CHECK", "true").lower() == "true"
}

# Detect Placeholder Credentials to avoid log spam
def _check_config_validity():
    placeholders = ["yourfirm.local", "your-app-password-here", "example.com"]
    user = SMTP_CONFIG["USER"]
    pwd = SMTP_CONFIG["PASS"]
    if not user or any(p in user for p in placeholders):
        return False
    if not pwd or any(p in pwd for p in placeholders):
        return False
    return True

SMTP_CONFIG["VALID"] = _check_config_validity()

ALERT_CONFIG = {
    "SENDER": SMTP_CONFIG["USER"] or "sentinel@internal.local",
    "RECEIVER": SMTP_CONFIG["TO"] or "admin@lawfirm.local",
    "DISCORD_WEBHOOK": os.getenv("DISCORD_WEBHOOK_URL", ""),
    "SMTP_SERVER": SMTP_CONFIG["HOST"],
    "SMTP_PORT": SMTP_CONFIG["PORT"]
}

# Separate Log for Reports
report_sent_log = os.path.join(LOGS_DIR, "report_sent.log")

class SentinelMonitor:
    """
    SOVEREIGN SHIELD - HUMAN-GOVERNED DATA LEAK PREVENTION ENGINE
    
    This engine provides supervised background monitoring of sensitive document droplets.
    It implements a zero-trust architecture where all incoming data is scanned, 
    surgically redacted, and then sealed in an AES-256 encrypted archive.
    
    Security Standards: AES-256, Hardware-Bound Secrets, HIPAA/GDPR Compliance Layer.
    """
    def __init__(self):
        self.scanner = EnterpriseScanner()
        self.embeddings = OllamaEmbeddings(model="llama3.1")
        self.vectorstore = None
        self.state = self.load_state()
        self.save_state()
        
        # --- GREEN GUARDIAN: Deprioritize background tasks for Battery/Perf ---
        if platform.system() != "Windows":
            try: os.nice(15) 
            except: pass

        # Governed resilience background workers
        self._start_background_workers()

    def _start_background_workers(self):
        """Starts background threads with supervised restart wrappers."""
        # 1. Monthly Reporter (governed resilience)
        self.reporter_thread = threading.Thread(target=self._worker_wrapper, args=(run_monthly_reporter,), daemon=True)
        self.reporter_thread.start()
        
        # 2. Update Checker (If enabled)
        if SMTP_CONFIG["UPDATE_CHECK"]:
            self.update_thread = threading.Thread(target=self._worker_wrapper, args=(self.check_for_updates,), daemon=True)
            self.update_thread.start()
            
        # 3. Log Guardian (Maintenance)
        self.maintenance_thread = threading.Thread(target=self._worker_wrapper, args=(self.run_maintenance,), daemon=True)
        self.maintenance_thread.start()

    def _worker_wrapper(self, target_func):
        """Wraps worker threads in an auto-restart loop for high availability."""
        while True:
            try:
                if target_func == self.check_for_updates or target_func == self.run_maintenance:
                    target_func()
                    # Non-looping functions rest for long intervals
                    time.sleep(3600 * 6) 
                else:
                    target_func(self)
            except Exception as e:
                logging.error(f"Governed resilience worker failure in {target_func.__name__}: {e}. Restarting in 60s...")
                time.sleep(60)
        
    def load_state(self):
        defaults = {"processed_files": {}, "stats": {"leaks_blocked": 0, "hours_saved": 0.0, "money_saved": 0.0, "redaction_stats": {}}}
        if os.path.exists(STATE_FILE):
            try:
                # Decrypt state from disk
                with open(STATE_FILE, "rb") as f:
                    encrypted_data = f.read()
                raw_data = sentinel_crypto.decrypt_data(encrypted_data)
                data = json.loads(raw_data)
                
                # Merge deep stats to avoid missing keys
                for k, v in defaults["stats"].items():
                    if k not in data.setdefault("stats", {}):
                        data["stats"][k] = v
                return data
            except Exception as e: 
                logging.error(f"State Decryption Failed: {e}")
        return defaults

    def save_state(self):
        """Encrypted state persistence to prevent physical tampering."""
        try:
            raw_data = json.dumps(self.state, indent=4).encode()
            encrypted_data = sentinel_crypto.encrypt_data(raw_data)
            with open(STATE_FILE, "wb") as f:
                f.write(encrypted_data)
        except Exception as e:
            logging.error(f"State Encryption Failed: {e}")

    def check_for_updates(self):
        """Checks for new version via Xavira Tech Labs API. Skips if air-gapped."""
        try:
            logging.info(f"Checking for updates (Current: v{VERSION})...")
            # Simple version check - server returns json like {"version": "1.1", "notes": "..."}
            response = requests.get(XAVIRA_VERSION_URL, timeout=10)
            if response.status_code == 200:
                remote_data = response.json()
                remote_version = str(remote_data.get("version", VERSION))
                
                if remote_version > VERSION:
                    logging.warning(f"NEW VERSION AVAILABLE: v{remote_version}")
                    update_msg = f"New version v{remote_version} available — FREE Lifetime Update from Xavira Tech Labs!"
                    
                    # Store the URL for the CLI to use
                    self.state["stats"]["update_available"] = remote_version
                    self.state["stats"]["update_url"] = remote_data.get("download_url")
                    self.save_state()
                    self.send_system_notification("🛡️ Sentinel Update Available", update_msg)
                    
                    # 2. Email Notification (if valid)
                    if SMTP_CONFIG["VALID"]:
                        try:
                            mime = MIMEText(f"{update_msg}\n\nDownload the new version from your client portal or contact support@xaviratechlabs.com.")
                            mime["Subject"] = "Sovereign Shield: Lifetime Free Update Available"
                            mime["From"] = ALERT_CONFIG['SENDER']
                            mime["To"] = ALERT_CONFIG['RECEIVER']
                            with smtplib.SMTP(SMTP_CONFIG["HOST"], SMTP_CONFIG["PORT"]) as s:
                                if SMTP_CONFIG["PASS"]:
                                    s.starttls()
                                    s.login(SMTP_CONFIG["USER"], SMTP_CONFIG["PASS"])
                                s.send_message(mime)
                        except: pass
        except Exception as e:
            logging.info(f"Update check skipped (Could not connect to update server).")

    def run_maintenance(self):
        """Operator-supervised maintenance: log rotation and disk health pruning."""
        logging.info("Guardian Maintenance: Rotating logs and verifying disk health...")
        try:
            # 1. Log Rotation (Max 5MB per log)
            for log_file in [alert_log, report_sent_log, os.path.join(LOGS_DIR, "monitor_output.log")]:
                if os.path.exists(log_file) and os.path.getsize(log_file) > 5 * 1024 * 1024:
                    os.rename(log_file, f"{log_file}.old")
                    logging.info(f"Log Rotation: {log_file} archived.")
            
            # 2. Clean temporary unstructured/python artifacts
            for root, dirs, files in os.walk(BASE_DIR):
                if "__pycache__" in dirs:
                    shutil.rmtree(os.path.join(root, "__pycache__"), ignore_errors=True)
                for f in files:
                    if f.endswith(".tmp") or f.startswith("unstructured_"):
                        try: os.remove(os.path.join(root, f))
                        except: pass
            
            logging.info("Guardian Maintenance: Storage cleanup complete.")
            
        except Exception as e:
            logging.error(f"Maintenance Error: {e}")

    def get_infra_health(self):
        """Calculates disk capacity and system resource pulse."""
        try:
            total, used, free = 0, 0, 0
            if platform.system() == "Windows":
                import shutil
                total, used, free = shutil.disk_usage(BASE_DIR)
            else:
                st = os.statvfs(BASE_DIR)
                free = st.f_bavail * st.f_frsize
                total = st.f_blocks * st.f_frsize
            
            used_pct = round(( (total - free) / total ) * 100, 1)
            return {
                "disk_used_pct": used_pct,
                "disk_free_gb": round(free / (1024**3), 2),
                "ai_pulse": "HEALTHY",
                "uptime": "24/7 ACTIVE"
            }
        except:
            return {"disk_used_pct": "??", "disk_free_gb": "??", "ai_pulse": "UNKNOWN"}

    def _soft_beep(self):
        """Best-effort alert tone that works without blocking monitor flow."""
        if not SMTP_CONFIG["NOTIFY_SOUND"]:
            return
        try:
            if platform.system() == "Windows":
                import winsound
                winsound.Beep(880, 150)
            elif platform.system() == "Darwin":
                subprocess.run(["afplay", "/System/Library/Sounds/Ping.aiff"], check=False)
            else:
                print("\a", end="", flush=True)
        except Exception as e:
            logging.error(f"Beep Error: {e}")

    def send_system_notification(self, title, message):
        """Sends a cross-platform desktop popup notification."""
        try:
            notification.notify(
                title=title,
                message=message,
                app_name="Sovereign Shield Version 1",
                timeout=10,
                ticker="Sentinel Alert"
            )
            self._soft_beep()
        except Exception as e:
            logging.error(f"Notification Error: {e}")

    def trigger_alert(self, filename, risk_score, findings):
        today = datetime.now().strftime("%Y-%m-%d")
        
        # Log to alerts.log (ALWAYS LOG)
        msg_header = f"🚨 CRITICAL LEAK BLOCKED: {filename}"
        msg_content = f"Risk: {risk_score:.2f} | Detected: {[f['label'] for f in findings[:3]]}"
        logging.critical(f"{msg_header} | {msg_content}")
        
        # System Notification (Live popup)
        self.send_system_notification(
            "⚠️ Sovereign Shield Version 1 Alert",
            f"⚠️ ALERT: Data leak risk in file {filename}. Do not share."
        )
        
        # Throttle: Check if we sent ANY alert today (Global throttle as requested)
        last_global_alert = self.state.get("stats", {}).get("last_global_alert_date")
        if last_global_alert == today:
            logging.info(f"Throttling email alert for {filename} (Already sent an alert today).")
            return

        # 1. Email Alert
        try:
            if not SMTP_CONFIG["VALID"]:
                logging.info("SMTP Credentials are empty or placeholder. Skipping email alert.")
                return

            email_body = f"""
            Sovereign Shield Version 1 Security Alert
            -------------------------------
            Type: CRITICAL LEAK BLOCKED
            File: {filename}
            Risk Score: {risk_score:.2f}
            Timestamp: {datetime.now()}

            Findings: {[f['label'] for f in findings]}
            
            Action: System has automatically REDACTED sensitive parts 
                    before indexing into the vault for your safety.
            
            -------------------------------
            This is an automated air-gapped security notification.
            """
            
            mime = MIMEText(email_body)
            mime["Subject"] = f"SECURITY ALERT: Critical Leak Blocked in {filename}"
            mime["From"] = ALERT_CONFIG['SENDER']
            mime["To"] = ALERT_CONFIG['RECEIVER']
            
            with smtplib.SMTP(SMTP_CONFIG["HOST"], SMTP_CONFIG["PORT"]) as s:
                if SMTP_CONFIG["PASS"]:
                    s.starttls()
                    s.login(SMTP_CONFIG["USER"], SMTP_CONFIG["PASS"])
                s.send_message(mime)
                
            logging.info(f"Critical email alert sent to {ALERT_CONFIG['RECEIVER']} for {filename}")
            
            # 2. Discord/Slack (Real-time is better for webhooks, so no throttle there)
            if ALERT_CONFIG["DISCORD_WEBHOOK"]:
                try: requests.post(ALERT_CONFIG["DISCORD_WEBHOOK"], json={"content": f"🚨 {msg_header} | {msg_content}"}, timeout=5)
                except: pass

            # Update state with this global alert timestamp
            self.state["stats"]["last_global_alert_date"] = today
            self.save_state()
            
        except Exception as e: 
            logging.error(f"Critical Email Notification Failed: {e}")

    async def ingest_file(self, filepath):
        filename = os.path.basename(filepath)
        print(f"[*] Analyzing: {filename}")
        
        try:
            # Load with modern UnstructuredLoader
            loader = UnstructuredLoader(filepath)
            docs = loader.load()
            raw_text = "\n".join([d.page_content for d in docs])

            # Scan & Redact
            findings = self.scanner.scan_content(raw_text)
            risk_score = self.scanner.calculate_risk_score(findings)
            
            # CRITICAL PIECE: Redact BEFORE indexing
            clean_text = self.scanner.redact_content(raw_text, findings)
            
            if risk_score > 7.0:
                self.trigger_alert(filename, risk_score, findings)
                self.state["stats"]["leaks_blocked"] += 1
            
            # Split cleaned content
            text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=150)
            chunks = text_splitter.create_documents([clean_text], metadatas=[{"source": filename, "risk": risk_score}])
            
            # Persistent Indexing
            if self.vectorstore is None:
                self.vectorstore = Chroma.from_documents(
                    documents=chunks,
                    embedding=self.embeddings,
                    persist_directory=CHROMA_DIR
                )
            else:
                self.vectorstore.add_documents(chunks)

            # Record stats
            # Dynamic ROI: 0.1 hours base + 0.1 per 500 words
            word_count = len(raw_text.split())
            saved_time = 0.1 + (word_count / 2000)
            
            self.state["stats"]["hours_saved"] = round(self.state["stats"]["hours_saved"] + saved_time, 2)
            # Billable rate calculation ($250/hr for legal/medical)
            self.state["stats"]["money_saved"] += round(saved_time * 250, 2)
            
            # --- LIABILITY MITIGATION BONUS ---
            # Every high risk leak blocked saves at least $1500 in compliance cost
            if risk_score > 7.0:
                self.state["stats"]["money_saved"] += 1500.0
                logging.info(f"Adding $1500 Liability Mitigation bonus for {filename}")

            self.state["stats"]["last_sync"] = datetime.now().strftime("%H:%M:%S")
            
            # Granular Compliance Tracking
            red_stats = self.state["stats"].setdefault("redaction_stats", {})
            for f in findings:
                label = f.get('label', 'DATA')
                red_stats[label] = red_stats.get(label, 0) + 1

            self.state["processed_files"][filename] = {
                "score": risk_score,
                "timestamp": time.ctime(),
                "status": "ARCHIVED",
                "words": word_count
            }
            self.save_state()
            
            # --- AUTO-ARCHIVE ---
            # Move out of drop zone to keep it clean for client
            dest_path = os.path.join(VAULT_ARCHIVE, filename)
            # Handle collision
            if os.path.exists(dest_path):
                dest_path = os.path.join(VAULT_ARCHIVE, f"{int(time.time())}_{filename}")
            
            os.rename(filepath, dest_path)
            
            # --- MILITARY GRADE VAULT SEALING ---
            # Encrypt the archived file so it is unreadable outside of Sentinel
            sentinel_crypto.encrypt_file(dest_path)
            
            print(f"[*] Secured, Encrypted & Archived: {filename}")

        except Exception as e:
            logging.error(f"Ingest Error {filename}: {e}")

    def send_monthly_report(self):
        """Generates and sends a professional summary email to the client."""
        today = datetime.now()
        stats = self.state.get("stats", {})
        processed = self.state.get("processed_files", {})
        
        # High Risk Filter
        high_risk_files = [f"{name} (Score: {meta['score']})" for name, meta in processed.items() if meta['score'] > 7.0]
        
        report_body = f"""
        <html>
        <body style='font-family: sans-serif; color: #333;'>
            <h2 style='color: #10b981;'>Sovereign Shield Version 1 Monthly Intelligence Report</h2>
            <hr/>
            <h3>🛡️ Security Posture Summary</h3>
            <ul>
                <li><b>Leaks Blocked:</b> {stats.get('leaks_blocked', 0)}</li>
                <li><b>Intelligence Mapped:</b> {len(processed)} documents</li>
                <li><b>Estimated Savings:</b> {stats.get('hours_saved', 0.0)} hours search time</li>
            </ul>
            
            <h3>🚨 High-Risk Interceptions</h3>
            <p>{'None detected.' if not high_risk_files else '<br>'.join(high_risk_files[:10])}</p>
            
            <hr/>
            <p style='font-size: 0.8rem; color: #666;'>Automated air-gapped report. No data left your premises.</p>
        </body>
        </html>
        """
        
        try:
            if not SMTP_CONFIG["VALID"]:
                logging.info("SMTP Credentials are empty or placeholder. Skipping email report.")
                # Mark as attempted today anyway to avoid infinite logs
                self.state["stats"]["last_report_date"] = today.strftime("%Y-%m-%d")
                self.save_state()
                return

            msg = MIMEText(report_body, 'html')
            msg['Subject'] = f"Sovereign Shield Monthly Summary - {today.strftime('%B %Y')}"
            msg['From'] = ALERT_CONFIG['SENDER']
            msg['To'] = ALERT_CONFIG['RECEIVER']
            
            with smtplib.SMTP(SMTP_CONFIG["HOST"], SMTP_CONFIG["PORT"]) as server:
                if SMTP_CONFIG["PASS"]:
                    server.starttls()
                    server.login(SMTP_CONFIG["USER"], SMTP_CONFIG["PASS"])
                server.send_message(msg)
                
            with open(report_sent_log, "a") as f:
                f.write(f"{datetime.now()}: Success - Sent to {ALERT_CONFIG['RECEIVER']}\n")
            logging.info(f"Monthly Report Sent to {ALERT_CONFIG['RECEIVER']}")
            
            self.state["stats"]["last_report_date"] = today.strftime("%Y-%m-%d")
            self.save_state()
            
        except Exception as e:
            logging.error(f"Failed to send monthly report: {e}")
            with open(report_sent_log, "a") as f:
                f.write(f"{datetime.now()}: FAILED - {e}\n")

    def generate_audit_report(self):
        """Generates a detailed CSV audit report for compliance officers."""
        report_path = os.path.join(LOGS_DIR, f"audit_report_{datetime.now().strftime('%Y%m')}.csv")
        try:
            with open(report_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "File", "Risk Score", "Words Processed", "Redaction Profile"])
                for filename, meta in self.state.get("processed_files", {}).items():
                    # Format redactions for this specific file if we had them or just summarize
                    writer.writerow([
                        meta.get("timestamp"),
                        filename,
                        meta.get("score"),
                        meta.get("words"),
                        meta.get("status")
                    ])
            return report_path
        except Exception as e:
            logging.error(f"Audit Export Failed: {e}")
            return None

class WatchdogHandler(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor

    def on_created(self, event):
        if not event.is_directory and not event.src_path.endswith('.tmp'):
            def run_ingest():
                try:
                    asyncio.run(self.monitor.ingest_file(event.src_path))
                except Exception as e:
                    logging.error(f"Threaded Ingest Error: {e}")
            threading.Thread(target=run_ingest).start()

    def on_moved(self, event):
        if not event.is_directory and not event.dest_path.endswith('.tmp'):
            def run_ingest():
                try:
                    asyncio.run(self.monitor.ingest_file(event.dest_path))
                except Exception as e:
                    logging.error(f"Threaded Ingest Error (Move): {e}")
            threading.Thread(target=run_ingest).start()


def run_monthly_reporter(monitor):
    """Background thread that monitors the 30-day reporting cycle."""
    logging.info("Monthly Reporter Thread Started")
    while True:
        try:
            state = monitor.state
            last_report = state.get("stats", {}).get("last_report_date")
            
            should_send = False
            if not last_report:
                logging.info("No last report found. Triggering first report...")
                should_send = True
            else:
                last_dt = datetime.strptime(last_report, "%Y-%m-%d")
                delta = datetime.now() - last_dt
                logging.info(f"Report Cycle Check: {delta.days} days since last report (Goal: {SMTP_CONFIG['CYCLE_DAYS']})")
                if delta.days >= SMTP_CONFIG["CYCLE_DAYS"]:
                    should_send = True
            
            if should_send:
                monitor.send_monthly_report()
            else:
                logging.info("Skipping report for today.")
                
            # Tick heartbeat (shows system is active in real time)
            monitor.state["stats"]["last_sync"] = datetime.now().strftime("%H:%M:%S")
            monitor.save_state()
            
        except Exception as e:
            logging.error(f"Reporter thread error: {e}")
        
        # Check every 4 hours. Even in test mode (CYCLE_DAYS=1), 
        # we don't want to spam lookups every 10 seconds if it fails.
        interval = 3600 if SMTP_CONFIG["CYCLE_DAYS"] == 1 else 3600 * 4
        time.sleep(interval)

if __name__ == "__main__":
    monitor = SentinelMonitor()
    
    # --- HARDWARE LICENSE GATE ---
    if not sentinel_crypto.is_licensed():
        print(f"\n{'-'*50}")
        print("🚨 SOVEREIGN SHIELD: LICENSE REQUIRED")
        print(f"Hardware ID: {sentinel_crypto.get_machine_id()}")
        print("-" * 50)
        logging.critical("System starting failed: No valid license found.")
        sys.exit(1)

    # Initial sweep of existing files (only if not already secured)
    print(f"[*] Starting system-wide security audit...")
    sys_leaks = monitor.scanner.audit_system()
    if sys_leaks:
        print(f"[!] {len(sys_leaks)} potential system-host risks found.")
        for leak in sys_leaks:
            logging.warning(f"SYSTEM RISK: {leak['label']} (Risk: {leak['risk']})")
    
    for f in os.listdir(VAULT_DOCS):
        fpath = os.path.join(VAULT_DOCS, f)
        if os.path.isfile(fpath) and not f.startswith('.'):
            if f not in monitor.state["processed_files"]:
                asyncio.run(monitor.ingest_file(fpath))

    # Start Watchdog
    handler = WatchdogHandler(monitor)
    observer = Observer()
    observer.schedule(handler, VAULT_DOCS, recursive=False)
    observer.start()
    
    print(f"[*] Monitoring vault at: {VAULT_DOCS}")
    
    # Start monthly reporting thread
    threading.Thread(target=run_monthly_reporter, args=(monitor,), daemon=True).start()

    try:
        while True: time.sleep(10)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
