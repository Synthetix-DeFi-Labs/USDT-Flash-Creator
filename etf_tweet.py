import tweepy
import sqlite3
import openai
import os

# Set OpenAI API key from environment variable
openai.api_key = os.getenv("OPENAI_API_KEY")

def get_keys_from_db():
    """Retrieve keys from the database"""
    conn = sqlite3.connect('keys.db')
    cursor = conn.cursor()
    cursor.execute("SELECT consumer_key, consumer_secret, access_token, access_secret FROM twitter_keys LIMIT 1")
    keys = cursor.fetchone()
    conn.close()
    return keys

def generate_etf_tweet(etf_name, repo_link, hashtags):
    """Generate a tweet using OpenAI GPT for ETF content"""
    prompt = f"Write a tweet about {etf_name} ETF, highlighting its latest trends. Include the repo link {repo_link} and use relevant hashtags {hashtags}. Keep it concise and engaging."
    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=prompt,
        max_tokens=60,
        temperature=0.7
    )
    return response.choices[0].text.strip()

def tweet(content):
    """Post a tweet using Twitter API"""
    consumer_key, consumer_secret, access_token, access_secret = get_keys_from_db()

    # Authenticate Twitter API
    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_token, access_secret)
    api = tweepy.API(auth)
    
    # Post tweet
    api.update_status(content)
    print(f"Tweeted: {content}")

# Example usage
etf_name = "Synthetix DeFi ETF"
repo_link = "https://github.com/Synthetix-DeFi-Labs/USDT-Flash-Creator"
hashtags = "#crypto #DeFi #ETF"
tweet_content = generate_etf_tweet(etf_name, repo_link, hashtags)

# Post the tweet
tweet(tweet_content)
