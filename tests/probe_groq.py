import asyncio
import json
import os
import sys

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.llm_client import LLMClient

async def probe_groq():
    """
    STRICT PROOF OF LIFE:
    Sends a real request to Groq 70B via the LLMClient.
    If it fails, it prints the raw error.
    No mock data.
    """
    client = LLMClient()
    
    # Check if key is even detected by the client
    if not client.groq_key:
        print("FAILURE: GROQ_API_KEY is not set in the environment.")
        return

    print(f"DEBUG: Found GROQ_API_KEY (starts with {client.groq_key[:4]}...)")
    print(f"DEBUG: Targeting model: {client.strategist_model}")

    prompt = "Reply with a JSON object containing the current timestamp and a logical proof that 1+1=2."
    
    print("\nPROBING GROQ API...")
    try:
        # Call Groq directly via the internal method to see raw results
        response = await client._call_groq(prompt, system_prompt="You are a logic verifier. RETURN JSON ONLY.")
        
        if "error" in response:
            print(f"FAILURE: Groq API returned an error: {json.dumps(response, indent=2)}")
        else:
            print(f"SUCCESS: Groq Brain is ONLINE. Raw response:\n{json.dumps(response, indent=2)}")
            
    except Exception as e:
        print(f"FAILURE: Exception during Groq probe: {str(e)}")

if __name__ == "__main__":
    asyncio.run(probe_groq())
