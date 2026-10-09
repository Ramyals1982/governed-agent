from llm import chat

response = chat([{"role": "user", "content": "Say hello in one sentence."}])
print(response.choices[0].message.content)
print("Model used:", response.model)