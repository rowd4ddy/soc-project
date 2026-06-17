import ollama
import os

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

def test_connection():
    client = ollama.Client(host=OLLAMA_HOST)
    response = client.chat(
        model="qwen2.5:7b",
        messages=[{"role": "user", "content": "Say hello in one sentence."}]
    )
    print("✅ Ollama connected!")
    print(response["message"]["content"])

if __name__ == "__main__":
    test_connection()