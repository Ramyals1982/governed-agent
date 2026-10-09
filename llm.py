import os
from openai import OpenAI

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.environ["OPENROUTER_API_KEY"],
)

MODEL = "deepseek/deepseek-chat"   # check the exact name on openrouter.ai/models

def chat(messages, tools=None):
    return client.chat.completions.create(
        model=MODEL,
        messages=messages,
        tools=tools,
        temperature=0,
    )