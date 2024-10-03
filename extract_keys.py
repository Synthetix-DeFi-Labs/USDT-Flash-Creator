import os
import re
import json
import time
import hmac
import base64
import hashlib
import logging
import asyncio
import aiohttp
import sqlite3
import threading
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from contextlib import contextmanager
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from aiohttp import ClientSession, TCPConnector
from concurrent.futures import ThreadPoolExecutor, as_completed
from ratelimit import limits, sleep_and_retry

# Configure advanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(processName)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('key_extractor.log'),
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler(
            'detailed.log',
            maxBytes=10485760,  # 10MB
            backupCount=5
        )
    ]
)

logger = logging.getLogger(__name__)

@dataclass
class TwitterKeys:
    """Data class for Twitter API credentials with validation"""
    consumer_key: str
    consumer_secret: str
    access_token: str
    access_secret: str
    valid_until: Optional[datetime] = None
    rate_limit_remaining: int = 180
    last_validated: Optional[datetime] = None

    def __post_init__(self):
        """Validate keys format after initialization"""
        self._validate_format()

    def _validate_format(self) -> None:
        """Validate key format and length"""
        validations = [
            (self.consumer_key, 25, "Consumer key"),
            (self.consumer_secret, 50, "Consumer secret"),
            (self.access_token, 50, "Access token"),
            (self.access_secret, 45, "Access secret")
        ]

        for value, min_length, name in validations:
            if not value or len(value) < min_length:
                raise ValueError(f"{name} is invalid or too short")

    def to_dict(self) -> dict:
        """Convert to dictionary with additional metadata"""
        return {
            **asdict(self),
            'last_validated_iso': self.last_validated.isoformat() if self.last_validated else None,
            'valid_until_iso': self.valid_until.isoformat() if self.valid_until else None
        }

class DatabaseManager:
    """Manage SQLite database operations for key storage"""
    def __init__(self, db_path: str = 'keys.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS twitter_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    consumer_key TEXT UNIQUE,
                    consumer_secret TEXT,
                    access_token TEXT,
                    access_secret TEXT,
                    valid_until TIMESTAMP,
                    rate_limit_remaining INTEGER,
                    last_validated TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_valid_until ON twitter_keys(valid_until)')

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {str(e)}")
            raise
        finally:
            conn.close()

    def save_keys(self, keys: TwitterKeys):
        """Save or update keys in database"""
        with self._get_connection() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO twitter_keys 
                (consumer_key, consumer_secret, access_token, access_secret, 
                valid_until, rate_limit_remaining, last_validated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                keys.consumer_key, keys.consumer_secret, keys.access_token,
                keys.access_secret, keys.valid_until, keys.rate_limit_remaining,
                keys.last_validated
            ))

class KeyEncryption:
    """Handle encryption and decryption of sensitive data"""
    def __init__(self, master_key: str):
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'twitter_key_salt',
            iterations=480000,
        )
        derived_key = base64.urlsafe_b64encode(self.kdf.derive(master_key.encode()))
        self.fernet = MultiFernet([Fernet(derived_key)])

    def encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        return self.fernet.decrypt(encrypted_data.encode()).decode()

class TwitterAPIValidator:
    """Validate Twitter API keys through actual API calls"""
    def __init__(self, session: Optional[ClientSession] = None):
        self.session = session
        self.base_url = "https://api.twitter.com/1.1"
        self._rate_limit_lock = threading.Lock()
        self._rate_limits = {}

    @sleep_and_retry
    @limits(calls=180, period=900)  # 180 calls per 15-minute window
    async def validate_keys(self, keys: TwitterKeys) -> bool:
        """Validate Twitter API keys by making a test request"""
        if not self.session:
            self.session = ClientSession(connector=TCPConnector(ssl=True))

        try:
            oauth_params = self._generate_oauth_params(keys)
            headers = {
                'Authorization': self._generate_oauth_header(oauth_params),
                'Content-Type': 'application/json',
            }

            async with self.session.get(
                f"{self.base_url}/account/verify_credentials.json",
                headers=headers
            ) as response:
                if response.status == 200:
                    keys.last_validated = datetime.now()
                    keys.valid_until = datetime.now() + timedelta(days=7)
                    return True
                return False

        except Exception as e:
            logger.error(f"API validation error: {str(e)}")
            return False

    def _generate_oauth_params(self, keys: TwitterKeys) -> Dict[str, str]:
        """Generate OAuth 1.0a parameters"""
        timestamp = str(int(time.time()))
        nonce = base64.b64encode(os.urandom(32)).decode()

        params = {
            'oauth_consumer_key': keys.consumer_key,
            'oauth_nonce': nonce,
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': timestamp,
            'oauth_token': keys.access_token,
            'oauth_version': '1.0'
        }

        # Generate signature
        signature_base = '&'.join([
            'GET',
            self._url_encode(f"{self.base_url}/account/verify_credentials.json"),
            self._url_encode('&'.join([
                f"{k}={self._url_encode(v)}"
                for k, v in sorted(params.items())
            ]))
        ])

        signing_key = f"{self._url_encode(keys.consumer_secret)}&{self._url_encode(keys.access_secret)}"
        signature = base64.b64encode(
            hmac.new(
                signing_key.encode(),
                signature_base.encode(),
                hashlib.sha1
            ).digest()
        ).decode()

        params['oauth_signature'] = signature
        return params

    def _generate_oauth_header(self, params: Dict[str, str]) -> str:
        """Generate OAuth authorization header"""
        return 'OAuth ' + ', '.join([
            f'{self._url_encode(k)}="{self._url_encode(v)}"'
            for k, v in sorted(params.items())
        ])

    @staticmethod
    def _url_encode(value: str) -> str:
        """URL encode string according to OAuth 1.0a specs"""
        return requests.utils.quote(value, safe='')

class KeyExtractor:
    """Main class for extracting and managing Twitter API keys"""
    def __init__(self, encryption_key: str, db_manager: DatabaseManager):
        self.encryption = KeyEncryption(encryption_key)
        self.db_manager = db_manager
        self.validator = TwitterAPIValidator()
        self.key_pattern = re.compile(
            r'TWITTER_CONSUMER_KEY="([^"]+)"\s+'
            r'TWITTER_CONSUMER_SECRET="([^"]+)"\s+'
            r'TWITTER_ACCESS_TOKEN="([^"]+)"\s+'
            r'TWITTER_ACCESS_SECRET="([^"]+)"'
        )

    async def process_file(self, file_path: str, max_keys: int = 20) -> List[TwitterKeys]:
        """Process file and extract valid Twitter keys"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()

            matches = self.key_pattern.findall(content)
            valid_keys = []

            async with ClientSession() as session:
                self.validator.session = session
                tasks = []

                for match in matches[:max_keys]:
                    try:
                        keys = TwitterKeys(
                            consumer_key=match[0],
                            consumer_secret=match[1],
                            access_token=match[2],
                            access_secret=match[3]
                        )
                        tasks.append(self.validator.validate_keys(keys))
                    except ValueError as e:
                        logger.warning(f"Skipping invalid key set: {str(e)}")
                        continue

                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for keys, is_valid in zip(matches[:max_keys], results):
                    if isinstance(is_valid, bool) and is_valid:
                        valid_keys.append(TwitterKeys(*keys))

            return valid_keys

        except Exception as e:
            logger.error(f"Error processing file: {str(e)}")
            raise

    def save_valid_keys(self, keys: List[TwitterKeys], output_file: str):
        """Save valid keys to both database and encrypted file"""
        try:
            # Save to database
            for key_set in keys:
                self.db_manager.save_keys(key_set)

            # Save encrypted version to file
            output_dir = os.path.dirname(output_file)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            with open(output_file, 'w') as f:
                encrypted_data = {
                    'timestamp': datetime.now().isoformat(),
                    'keys': [self.encryption.encrypt(json.dumps(key.to_dict())) for key in keys]
                }
                json.dump(encrypted_data, f, indent=2)

            logger.info(f"Successfully saved {len(keys)} valid keys to {output_file}")
            return len(keys)

        except Exception as e:
            logger.error(f"Error saving keys: {str(e)}")
            raise

async def main():
    """Main function to run the key extraction process"""
    try:
        # Load configuration from environment
        config = {
            'max_keys': int(os.getenv('MAX_KEYS', '20')),
            'output_file': os.getenv('OUTPUT_FILE', 'keys/valid_keys.json'),
            'encryption_key': os.getenv('ENCRYPTION_KEY'),
            'input_file': os.getenv('INPUT_FILE'),
            'db_path': os.getenv('DB_PATH', 'keys.db')
        }

        if not config['encryption_key']:
            raise ValueError("Encryption key is required")

        # Initialize components
        db_manager = DatabaseManager(config['db_path'])
        extractor = KeyExtractor(config['encryption_key'], db_manager)

        # Process input file
        if not config['input_file'] or not os.path.exists(config['input_file']):
            raise FileNotFoundError("Input file not found")

        valid_keys = await extractor.process_file(
            config['input_file'],
            config['max_keys']
        )

        if not valid_keys:
            logger.warning("No valid keys found")
            return 1

        # Save valid keys
        saved_count = extractor.save_valid_keys(valid_keys, config['output_file'])
        logger.info(f"Successfully processed and saved {saved_count} valid keys")
        return 0

    except Exception as e:
        logger.error(f"Critical error in main process: {str(e)}")
        return 1

if __name__ == "__main__":
    asyncio.run(main())
