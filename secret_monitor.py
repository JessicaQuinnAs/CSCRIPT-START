import os
import asyncio
import threading
import logging
import zipfile
import tarfile
import requests
import sqlite3
import base58
import math
import re
from collections import Counter
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from PIL import Image
import pytesseract  # OCR library
import dns.resolver
from fastapi import FastAPI, Request, Header, HTTPException
from uvicorn import run as uvicorn_run
from dotenv import load_dotenv

# === Load configuration from .env or environment ===
load_dotenv()
WEBSOCKET_URI        = os.getenv('WEBSOCKET_URI', 'wss://example.com/stream')
WATCHED_PATH         = os.getenv('WATCHED_PATH', '.')
GITHUB_WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET', '')
DATABASE_URL         = os.getenv('DATABASE_URL', 'secrets.db')
DNS_DOMAINS          = os.getenv('DNS_DOMAINS', 'leak.com').split(',')
BTC_ADDRESSES        = os.getenv('BTC_ADDRESSES', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa').split(',')
PERIODIC_INTERVAL    = int(os.getenv('PERIODIC_INTERVAL', '3600'))  # seconds
PORT                 = int(os.getenv('PORT', '8000'))
LOG_FILE             = os.getenv('LOG_FILE', 'secret_monitor.log')

# === Configure logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

# === Database setup ===
def init_db():
    conn = sqlite3.connect(DATABASE_URL, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            hash TEXT PRIMARY KEY,
            author TEXT,
            timestamp TEXT
        );
    """)
    conn.commit()
    return conn

db_conn = init_db()

# === Secret detection core ===
def calculate_entropy(data: str) -> float:
    probabilities = [n_x / len(data) for _, n_x in Counter(data).items()]
    return -sum(p * math.log2(p) for p in probabilities)

def detect_secret(content: str) -> bool:
    try:
        decoded = base58.b58decode_check(content)
        if len(decoded) in (32, 33):
            return True
    except Exception:
        pass
    if len(content) > 10 and calculate_entropy(content) > 4.5:
        return True
    return False

# === Layers implementations ===
async def websocket_monitor(uri: str):
    import websockets
    while True:
        try:
            async with websockets.connect(uri) as ws:
                logging.info(f"WebSocket connected: {uri}")
                async for message in ws:
                    if detect_secret(message):
                        logging.warning(f"Secret detected in WebSocket stream: {message}")
        except Exception as e:
            logging.error(f"WebSocket error: {e}, reconnecting in 5s...")
            await asyncio.sleep(5)

def analyze_git_diff(diff_content: str):
    if detect_secret(diff_content):
        logging.warning(f"Secret detected in Git diff: {diff_content}")

def analyze_archives(file_path: str):
    try:
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as z:
                for name in z.namelist():
                    if is_sensitive_file(name):
                        data = z.read(name).decode(errors='ignore')
                        if detect_secret(data):
                            logging.warning(f"Secret in {file_path}:{name}")
        elif file_path.endswith(('.tar.gz', '.tgz')):
            with tarfile.open(file_path, 'r:gz') as t:
                for member in t.getmembers():
                    if is_sensitive_file(member.name):
                        f = t.extractfile(member)
                        if f:
                            data = f.read().decode(errors='ignore')
                            if detect_secret(data):
                                logging.warning(f"Secret in {file_path}:{member.name}")
    except Exception as e:
        logging.error(f"Archive parsing error ({file_path}): {e}")

def ocr_image(image_path: str):
    try:
        text = pytesseract.image_to_string(Image.open(image_path))
        if detect_secret(text):
            logging.warning(f"Secret via OCR in {image_path}: {text}")
    except Exception as e:
        logging.error(f"OCR error ({image_path}): {e}")

def detect_dns_leak(domain: str):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for ip in answers:
            logging.warning(f"DNS leak: {domain} -> {ip}")
    except dns.resolver.NXDOMAIN:
        pass
    except Exception as e:
        logging.error(f"DNS error ({domain}): {e}")

# === Reuse/fingerprint storage ===
def check_database_reuse(secret_hash: str) -> bool:
    cur = db_conn.cursor()
    cur.execute("SELECT 1 FROM secrets WHERE hash = ?", (secret_hash,))
    return cur.fetchone() is not None

def store_secret(secret_hash: str, author: str) -> str:
    ts = datetime.utcnow().isoformat()
    try:
        cur = db_conn.cursor()
        cur.execute(
            "INSERT INTO secrets(hash, author, timestamp) VALUES (?, ?, ?)",
            (secret_hash, author, ts)
        )
        db_conn.commit()
    except sqlite3.IntegrityError:
        pass
    return ts

def detect_reuse(secret: str, author: str):
    h = hashlib.sha256(secret.encode()).hexdigest()
    if check_database_reuse(h):
        logging.warning(f"Reuse detected: {h} by {author}")
    else:
        ts = store_secret(h, author)
        logging.info(f"Stored new secret: {h} by {author} at {ts}")

def fingerprint_secret(secret: str, author: str='unknown'):
    detect_reuse(secret, author)

def generate_weak_bip39_mnemonics():
    return ["abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"]

def check_btc_balance(address: str):
    try:
        res = requests.get(f"https://blockchain.info/q/addressbalance/{address}")
        sat = int(res.text)
        btc = sat / 1e8
        if btc > 0:
            logging.warning(f"Non-zero balance: {address} -> {btc} BTC")
    except Exception as e:
        logging.error(f"BTC balance error ({address}): {e}")

def is_sensitive_file(name: str) -> bool:
    return name.endswith(('.env', 'wallet.dat', 'key.txt'))

# === FastAPI GitHub Webhook ===
app = FastAPI()

@app.post("/webhook")
async def github_webhook(request: Request, x_hub_signature_256: str = Header(None)):
    body = await request.body()
    if GITHUB_WEBHOOK_SECRET:
        import hmac, hashlib
        sig = 'sha256=' + hmac.new(
            GITHUB_WEBHOOK_SECRET.encode(), body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, x_hub_signature_256 or ''):
            raise HTTPException(status_code=403, detail='Invalid signature')
    payload = await request.json()
    if 'commits' in payload:
        for commit in payload['commits']:
            diff_url = commit['url'] + '.diff'
            r = requests.get(diff_url)
            if r.ok:
                analyze_git_diff(r.text)
    elif 'pull_request' in payload:
        files = payload.get('pull_request', {}).get('changed_files', [])
        for f in files:
            analyze_git_diff(f.get('patch', ''))
    return {'status':'ok'}

# === Watchdog handler ===
class SecretEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        logging.info(f"New file: {path}")
        if path.endswith(('.zip', '.tar.gz', '.tgz')):
            analyze_archives(path)
        elif path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
            ocr_image(path)

# === Orchestration ===
async def periodic_tasks():
    while True:
        for d in DNS_DOMAINS:
            detect_dns_leak(d)
        for addr in BTC_ADDRESSES:
            check_btc_balance(addr)
        await asyncio.sleep(PERIODIC_INTERVAL)

async def orchestrator():
    # Start FastAPI server
    def start_api():
        uvicorn_run(app, host='0.0.0.0', port=PORT, log_level='info')
    threading.Thread(target=start_api, daemon=True).start()
    logging.info(f"GitHub webhook server on port {PORT}")

    # Start WebSocket monitor with auto-reconnect
    ws_task = asyncio.create_task(websocket_monitor(WEBSOCKET_URI))
    # Start periodic DNS/BTC checks
    periodic_task = asyncio.create_task(periodic_tasks())

    # Start Watchdog observer
    handler = SecretEventHandler()
    observer = Observer()
    observer.schedule(handler, path=WATCHED_PATH, recursive=True)
    observer.start()
    logging.info(f"Watching path: {WATCHED_PATH}")

    # Keep the main task alive
    await asyncio.Event().wait()

if __name__ == '__main__':
    try:
        asyncio.run(orchestrator())
    except KeyboardInterrupt:
        logging.info("Interrupted, exiting...")