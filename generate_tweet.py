import openai
import os

openai.api_key = os.getenv("OPENAI_API_KEY")  # OpenAI API key from Dependabot secret

def generate_tweet(repo_link, hashtags):
    """Generate a tweet using OpenAI GPT"""
    prompt = f"Write a tweet for the latest contribution at {repo_link} with hashtags {hashtags}. Keep it concise and engaging."
    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=prompt,
        max_tokens=60,
        temperature=0.7
    )
    return response.choices[0].text.strip()

# Example usage
repo_link = "https://github.com/Synthetix-DeFi-Labs/USDT-Flash-Creator"
hashtags = "#crypto #DeFi #Synthetix"
tweet = generate_tweet(repo_link, hashtags)
print(tweet)
