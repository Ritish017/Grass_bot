import requests
import logging
import random
import json
import os
import time
import threading
from typing import Optional
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import sys

# Configuration (loaded from environment variables)
API_BASE_URL = "https://api.getgrass.io"
SNAPSHOT_FILE = Path("grass_session_snapshot.json")
KEY_FILE = Path("encryption_key.key")
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]
PUBLIC_PROXY_LIST = [
    "http://103.174.102.133:80",
    "http://167.71.5.83:3128",
    "http://47.251.43.115:33333"
]

# Load environment variables
def load_config():
    return {
        "AUTH_TOKEN": os.getenv("GRASS_AUTH_TOKEN", "INSERT_TOKEN_FROM_STEP_2"),
        "TELEGRAM_BOT_TOKEN": os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN"),
        "TELEGRAM_CHAT_ID": os.getenv("TELEGRAM_CHAT_ID", "YOUR_CHAT_ID"),
        "PRIMARY_PROXY": os.getenv("PRIMARY_PROXY", "http://<address>:<port>")
    }

CONFIG = load_config()

# Encryption setup
def generate_key(password: str = "default_password") -> bytes:
    """Generate an encryption key from a password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"grass_salt",
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_token(token: str, key: bytes) -> bytes:
    """Encrypt a token using Fernet."""
    f = Fernet(key)
    return f.encrypt(token.encode())

def decrypt_token(encrypted_token: bytes, key: bytes) -> str:
    """Decrypt a token using Fernet."""
    f = Fernet(key)
    return f.decrypt(encrypted_token).decode()

def load_or_generate_key() -> bytes:
    """Load encryption key or generate a new one."""
    if KEY_FILE.exists():
        with KEY_FILE.open("rb") as f:
            return f.read()
    key = generate_key()
    with KEY_FILE.open("wb") as f:
        f.write(key)
    return key

ENCRYPTION_KEY = load_or_generate_key()
ENCRYPTED_AUTH_TOKEN = encrypt_token(CONFIG["AUTH_TOKEN"], ENCRYPTION_KEY)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("grass_bot.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Custom exception
class GrassAPIError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Grass API Error {status_code}: {message}")

# Telegram notifications
TELEGRAM_API_URL = f"https://api.telegram.org/bot{CONFIG['TELEGRAM_BOT_TOKEN']}"

def send_telegram_message(message: str) -> bool:
    url = f"{TELEGRAM_API_URL}/sendMessage"
    payload = {"chat_id": CONFIG["TELEGRAM_CHAT_ID"], "text": message}  # Plain text, no Markdown
    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        return response.json().get("ok")
    except requests.RequestException as e:
        logger.error(f"Telegram send failed: {e} - Response: {e.response.text if e.response else 'No response'}")
        return False

def notify_farming_progress(source: str, volume: int, duration: int, earned_points: Optional[float] = None) -> bool:
    status = "Completed" if earned_points is not None else "Started"
    points_info = f" - Earned: {earned_points} points" if earned_points is not None else ""
    message = f"Farming {status}\nSource: {source}\nVolume: {volume} MB\nDuration: {duration} seconds{points_info}"
    return send_telegram_message(message)

def notify_points_balance(balance: float) -> bool:
    message = f"Points Balance Update\nCurrent Balance: {balance} points"
    return send_telegram_message(message)

# Session utilities
def save_session_snapshot(session: requests.Session, earned_points: float):
    snapshot = {
        "headers": dict(session.headers),
        "proxies": session.proxies,
        "last_earned_points": earned_points,
        "timestamp": datetime.now().isoformat()
    }
    with SNAPSHOT_FILE.open("w") as f:
        json.dump(snapshot, f, indent=2)

def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS)

def setup_session(proxy: str) -> requests.Session:
    session = requests.Session()
    decrypted_token = decrypt_token(ENCRYPTED_AUTH_TOKEN, ENCRYPTION_KEY)
    session.headers.update({
        "Authorization": f"Bearer {decrypted_token}",
        "Content-Type": "application/json",
        "User-Agent": get_random_user_agent()
    })
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session

def test_proxy(proxy: str) -> bool:
    try:
        response = requests.get("https://api.ipify.org", proxies={"http": proxy, "https": proxy}, timeout=5)
        response.raise_for_status()
        return True
    except requests.RequestException:
        return False

# API functions
def get_points_balance() -> Optional[float]:
    url = f"{API_BASE_URL}/user/points"
    session = setup_session(None)  # No proxy

    try:
        response = session.get(url, timeout=10)
        if response.status_code == 200:
            points = response.json().get("points")
            if points is not None:
                logger.info(f"Current points: {points}")
                notify_points_balance(points)
                return float(points)
            return None
        elif response.status_code in (401, 403):
            raise GrassAPIError(response.status_code, "Authentication or permission error")
        else:
            raise GrassAPIError(response.status_code, "Unexpected error")
    except requests.RequestException as e:
        logger.error(f"Balance check failed: {e}")
        return None

def farm_points(source: str, volume: int, duration: int) -> Optional[float]:
    url = f"{API_BASE_URL}/traffic/farm"
    payload = {"traffic_source": source, "traffic_volume": volume, "duration": duration}
    session = setup_session(None)  # No proxy

    logger.info(f"Starting farming: source={source}, volume={volume}, duration={duration}s")
    notify_farming_progress(source, volume, duration)

    try:
        response = session.post(url, json=payload, timeout=10)
        if response.status_code in (200, 201):
            earned_points = response.json().get("earned_points")
            if earned_points is not None:
                logger.info(f"Farmed {earned_points} points")
                save_session_snapshot(session, earned_points)
                notify_farming_progress(source, volume, duration, earned_points)
                return float(earned_points)
            return None
        elif response.status_code in (401, 403, 429):
            raise GrassAPIError(response.status_code, "API restriction encountered")
        else:
            raise GrassAPIError(response.status_code, "Unexpected error")
    except requests.RequestException as e:
        logger.error(f"Farming failed: {e}")
        return None

# Main bot logic
def run_bot():
    start_time = datetime.now()
    end_time = start_time + timedelta(hours=24)
    
    while datetime.now() < end_time:
        try:
            earned = farm_points("test_source", 100, 60)
            if earned:
                get_points_balance()
            time.sleep(300)  # 5-minute interval
        except Exception as e:
            logger.error(f"Bot crashed: {e}")
            time.sleep(60)  # Wait before restart
            continue

def restart_on_failure():
    while True:
        logger.info("Starting bot instance")
        bot_thread = threading.Thread(target=run_bot)
        bot_thread.start()
        bot_thread.join()  # Wait for thread to finish (24 hours or crash)
        logger.info("Bot instance finished or crashed, restarting in 10 seconds")
        time.sleep(10)

if __name__ == "__main__":
    logger.info("Grass Bot initialized")
    restart_on_failure()