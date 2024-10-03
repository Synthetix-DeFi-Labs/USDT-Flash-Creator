import tweepy
import os

def tweet(content):
    """Post a tweet using Twitter API"""
    auth = tweepy.OAuthHandler(os.getenv("TWITTER_CONSUMER_KEY_1"), os.getenv("TWITTER_CONSUMER_SECRET_1"))
    auth.set_access_token(os.getenv("TWITTER_ACCESS_TOKEN_1"), os.getenv("TWITTER_ACCESS_SECRET_1"))
    api = tweepy.API(auth)
    
    api.update_status(content)
    print(f"Tweeted: {content}")

# Example usage
tweet("New contribution to Synthetix Labs! 🚀 #crypto #DeFi #Synthetix")
