import requests
import logging
import random
import json
import os
import time
import sys
from typing import Optional
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import getpass
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type

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

# Logging setup (moved before load_config)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("grass_bot.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Load and validate environment variables
def load_config():
    config = {
        "AUTH_TOKEN": os.getenv("GRASS_AUTH_TOKEN"),
        "TELEGRAM_BOT_TOKEN": os.getenv("TELEGRAM_BOT_TOKEN"),
        "TELEGRAM_CHAT_ID": os.getenv("TELEGRAM_CHAT_ID"),
        "PRIMARY_PROXY": os.getenv("PRIMARY_PROXY", None)  # Optional proxy
    }
    if not config["AUTH_TOKEN"]:
        logger.error("GRASS_AUTH_TOKEN is required. Set it in environment variables.")
        sys.exit(1)
    if not (config["TELEGRAM_BOT_TOKEN"] and config["TELEGRAM_CHAT_ID"]):
        logger.warning("Telegram notifications disabled due to missing bot token or chat ID")
        config["TELEGRAM_BOT_TOKEN"] = None
        config["TELEGRAM_CHAT_ID"] = None
    return config

CONFIG = load_config()

# Encryption setup
def generate_key(password: str) -> bytes:
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
    """Load encryption key or generate a new one with user input."""
    if os.getenv("ENCRYPTION_PASSWORD"):
        return generate_key(os.getenv("ENCRYPTION_PASSWORD"))
    if KEY_FILE.exists():
        with KEY_FILE.open("rb") as f:
            return f.read()
    password = getpass.getpass("Enter encryption password: ")
    key = generate_key(password)
    with KEY_FILE.open("wb") as f:
        f.write(key)
    return key

ENCRYPTION_KEY = load_or_generate_key()
ENCRYPTED_AUTH_TOKEN = encrypt_token(CONFIG["AUTH_TOKEN"], ENCRYPTION_KEY)

# Custom exception
class GrassAPIError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Grass API Error {status_code}: {message}")

# Telegram notifications
TELEGRAM_API_URL = f"https://api.telegram.org/bot{CONFIG['TELEGRAM_BOT_TOKEN']}" if CONFIG["TELEGRAM_BOT_TOKEN"] else None

def send_telegram_message(message: str) -> bool:
    if not TELEGRAM_API_URL or not CONFIG["TELEGRAM_CHAT_ID"]:
        return False
    url = f"{TELEGRAM_API_URL}/sendMessage"
    payload = {"chat_id": CONFIG["TELEGRAM_CHAT_ID"], "text": message}
    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        return response.json().get("ok")
    except requests.RequestException as e:
        logger.error(f"Telegram send failed: {e}")
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

def load_session_snapshot() -> Optional[requests.Session]:
    if SNAPSHOT_FILE.exists():
        with SNAPSHOT_FILE.open("r") as f:
            snapshot = json.load(f)
        session = requests.Session()
        session.headers.update(snapshot["headers"])
        session.proxies = snapshot["proxies"]
        return session
    return None

def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS)

def test_proxy(proxy: str) -> bool:
    try:
        response = requests.get("https://api.ipify.org", proxies={"http": proxy, "https": proxy}, timeout=5)
        response.raise_for_status()
        return True
    except requests.RequestException:
        return False

def get_working_proxy() -> Optional[str]:
    proxies = PUBLIC_PROXY_LIST + ([CONFIG["PRIMARY_PROXY"]] if CONFIG["PRIMARY_PROXY"] else [])
    for proxy in proxies:
        if test_proxy(proxy):
            logger.info(f"Using proxy: {proxy}")
            return proxy
    logger.warning("No working proxies found, proceeding without proxy")
    return None

def setup_session() -> requests.Session:
    session = load_session_snapshot() or requests.Session()
    if not session.headers.get("Authorization"):
        decrypted_token = decrypt_token(ENCRYPTED_AUTH_TOKEN, ENCRYPTION_KEY)
        session.headers.update({
            "Authorization": f"Bearer {decrypted_token}",
            "Content-Type": "application/json",
            "User-Agent": get_random_user_agent()
        })
    proxy = get_working_proxy()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session

# API functions
@retry(
    wait=wait_exponential(multiplier=1, min=4, max=60),
    stop=stop_after_attempt(5),
    retry=retry_if_exception_type((requests.RequestException, GrassAPIError))
)
def get_points_balance() -> Optional[float]:
    url = f"{API_BASE_URL}/user/points"
    session = setup_session()

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

@retry(
    wait=wait_exponential(multiplier=1, min=4, max=60),
    stop=stop_after_attempt(5),
    retry=retry_if_exception_type((requests.RequestException, GrassAPIError))
)
def farm_points(source: str, volume: int, duration: int) -> Optional[float]:
    url = f"{API_BASE_URL}/traffic/farm"
    payload = {"traffic_source": source, "traffic_volume": volume, "duration": duration}
    session = setup_session()

    logger.info(f"Starting farming: source={source}, volume={volume}, duration={duration}s")
    notify_farming_progress(source, volume, duration)

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

# Main bot logic
def run_bot():
    logger.info("Grass Bot initialized")
    while True:
        try:
            start_time = datetime.now()
            end_time = start_time + timedelta(hours=24)
            
            while datetime.now() < end_time:
                earned = farm_points("test_source", 100, 60)
                if earned:
                    get_points_balance()
                time.sleep(300)  # 5-minute interval
            logger.info("24-hour cycle complete, restarting")
        except Exception as e:
            logger.error(f"Bot crashed: {e}")
            time.sleep(60)  # Backoff before retry
            continue

if __name__ == "__main__":
    run_bot()