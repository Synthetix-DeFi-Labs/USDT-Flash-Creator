import openai
import os

openai.api_key = os.getenv("OPENAI_API_KEY")  # OpenAI API key from your secrets

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

# Example usage
etf_name = "Synthetix DeFi ETF"
repo_link = "https://github.com/Synthetix-DeFi-Labs/USDT-Flash-Creator"
hashtags = "#crypto #DeFi #ETF"
tweet = generate_etf_tweet(etf_name, repo_link, hashtags)
print(tweet)
