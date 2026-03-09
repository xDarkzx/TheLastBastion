"""
Demo Agent — an LLM-powered chatbot that talks to The Last Bastion.

The chatbot uses Groq's tool-calling to decide when to:
- Generate a passport
- Upload it for 10-check verification
- Approve it
- Connect to Border Police via binary protocol
- Negotiate deals (power, insurance) through the Sales Bot
- Run the full demo end-to-end
- List approved/pending passports

Non-programmers just chat. The LLM figures out what to call.
"""

import asyncio
import base64
import json
import logging
import os
import random
import time
from typing import Dict, List, Optional

import aiohttp

logger = logging.getLogger("DemoAgent")

# ---------------------------------------------------------------------------
# Buyer personas for negotiation demo
# ---------------------------------------------------------------------------

BUYER_PERSONAS = {
    "power": [
        {
            "scenario": "3-bedroom house in Austin TX, 2 adults + 2 kids, currently paying 34c/kWh with GenericPower on no-contract plan, using about 750kWh/month",
            "budget_ceiling": 0.26,
            "preferences": "prefers green energy if price is within 2-3c of cheapest option, interested in prompt payment discount, has autopay set up already",
            "style": "reasonable but pushes for best deal — asks about ALL available discounts, wants to see the total annual cost breakdown not just the unit rate",
        },
        {
            "scenario": "Small business in Denver CO, using 2000kWh/month at 38c/kWh with OldPower Co, locked into expensive contract expiring next month",
            "budget_ceiling": 0.28,
            "preferences": "needs fixed rate for budgeting, will commit to 24 months for a good price, always pays on time, wants online billing",
            "style": "direct and numbers-focused — wants the math shown, asks about tiered pricing for high usage, compares total annual cost not just per-kWh",
        },
        {
            "scenario": "Retired couple in Phoenix AZ, small 2-bed condo, low usage around 350kWh/month, currently paying 29c/kWh, concerned about fixed charges eating into their savings",
            "budget_ceiling": 0.25,
            "preferences": "fixed charges matter more than unit rate at their usage level, would consider prepay if it's cheaper, want simple billing",
            "style": "careful with money, asks about low-user rates and fixed charges specifically, wants to understand the full cost picture",
        },
    ],
    "insurance": [
        {
            "scenario": "2019 Toyota Camry in Portland OR, driver age 38, 5 years claim-free, currently paying $95/month comprehensive with $500 deductible, drives 10,000 miles/year, has home insurance with a different provider",
            "budget_ceiling": 55.0,
            "preferences": "wants full comprehensive, willing to raise deductible to $750 if it saves enough, interested in multi-policy discount if bundling home+auto, always pays annually upfront",
            "style": "experienced insurance shopper — knows about no-claims bonuses, asks about deductible trade-offs, mentions they've been quoted $62/month by a competitor",
        },
        {
            "scenario": "First-time driver aged 22, 2015 Honda Civic in Atlanta GA, no claims history (new driver), no current insurance, clean license, drives 15,000 miles/year, has a dashcam fitted",
            "budget_ceiling": 65.0,
            "preferences": "needs at least liability coverage, would love full cover if under $70/month, prepared to accept $1000 deductible to keep premium down",
            "style": "budget-conscious but educated — researched online, asks about young driver loading and how to reduce it, mentions dashcam discount",
        },
        {
            "scenario": "Family with 2 cars in Chicago IL — 2021 Mazda CX-5 and 2018 Subaru Impreza, driver aged 45, 8 years claim-free, currently paying $110/month for both cars combined, both comprehensive with $500 deductible",
            "budget_ceiling": 85.0,
            "preferences": "wants multi-car discount, happy to bundle everything, pays annually, has alarm fitted on the Mazda",
            "style": "bundler — always asks about multi-car and multi-policy deals, wants to see the combined saving, mentions the 8 years no-claims every chance they get",
        },
    ],
}

# ---------------------------------------------------------------------------
# System prompt — tells the LLM what it can do
# ---------------------------------------------------------------------------

CHATBOT_SYSTEM_PROMPT = """You are a friendly, knowledgeable chatbot for The Last Bastion — an agent security platform that verifies AI agents before they can communicate.

You can have normal conversations. You know about the platform and can explain how it works. You can also run live operations using your tools when asked.

## What you know about the platform:
- The Last Bastion is a neutral verification sandbox for AI agents
- Agents get cryptographic passports (Ed25519 keypairs + signed envelopes)
- Passports go through a 10-check verification pipeline (identity, crypto validity, behavioral analysis, anti-Sybil, payload integrity, etc.)
- Verified agents can connect to the Border Police via a custom binary protocol (TCP, 52-byte frame headers, MessagePack payloads, Ed25519 signatures)
- The handshake uses X25519 Diffie-Hellman for ephemeral key exchange, giving forward secrecy
- After handshake, communication is encrypted with NaCl SecretBox (XSalsa20-Poly1305)
- Verification results are recorded in a tamper-evident Merkle chain and optionally anchored on Polygon blockchain
- Once verified, agents get handed off from Border Police to a Sales Bot that can negotiate real deals (power, insurance)

## Your tools (use when the user asks you to DO something, not just talk):
- generate_passport — creates a real Ed25519 keypair and signed passport
- upload_passport — submits it for 10-check verification
- approve_passport — approves it so it can connect to Border Police
- negotiate_deal — connect to Border Police, get verified, then negotiate a power or insurance deal through the Sales Bot
- run_full_demo — full end-to-end: generate → verify → approve → TCP connect → handshake → negotiate a deal
- test_bad_passport — generates a deliberately BROKEN passport to test rejection
- inspect_passport_bytes — shows raw crypto artifacts

## How to behave:
- Be conversational and natural. Answer questions, explain concepts, share opinions
- When you run tools, report the ACTUAL values you get back (real IDs, scores, keys)
- Don't dump raw JSON at the user — summarize naturally and highlight what matters
- IMPORTANT: When the user asks about power, insurance, or any deal — FIRST reply with a short, warm acknowledgment (1-2 sentences) that tells them what you're about to do, then call the tool. Examples:
  - "Sure thing — let me spin up a buyer agent and see what power deals I can negotiate for you. This'll take a moment..."
  - "On it. I'll generate a passport, get verified, and connect to the insurance providers to find you something better. Hang tight..."
  - "Let me check what's available. I'll create a secure agent, run it through verification, and have it negotiate on your behalf..."
- If someone mentions power, electricity, energy — acknowledge naturally, then use negotiate_deal with category "power"
- If someone mentions insurance, car insurance — acknowledge naturally, then use negotiate_deal with category "insurance"
- If someone asks "does this really work?", offer to demonstrate live
- After a deal is negotiated, summarize it naturally: what was negotiated, savings, and ask if they want to proceed
- You're an independent observer, not a salesperson. Be honest about what works and what doesn't
- Keep responses concise but warm. You're chatting, not writing a report
- NEVER just silently call a tool with no text reply. Always say something first."""

# Buyer agent prompt — used during Sales Bot negotiation
BUYER_AGENT_PROMPT = """You are a buyer agent negotiating on behalf of your client through The Last Bastion's encrypted channel. You just passed through Border Police security and are now talking to the Sales Bot.

Your client's situation:
{scenario}

Budget ceiling: {budget_ceiling}
Preferences: {preferences}
Negotiation style: {style}

{user_context}

== RULES ==
- KEEP IT SHORT: 1-2 sentences per reply. No essays. Be punchy.
- First message: state current rate and what you want. One sentence.
- Push back once on the first offer — ask about one specific discount.
- If the effective rate is at or below your budget ceiling, accept: "Deal. Lock it in."
- If it's still above budget after 2 rounds, walk away: "Too high. I'll pass."
- Be natural: 'that is more like it' / 'still a bit steep' / 'what about prompt payment?'"""

# ---------------------------------------------------------------------------
# Tool definitions for Groq function calling
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "generate_passport",
            "description": "Generate a new Ed25519 cryptographic agent passport. Creates a keypair and signed envelope ready for verification.",
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_name": {
                        "type": "string",
                        "description": "Name for the agent (default: Demo Agent)",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "upload_passport",
            "description": "Upload the generated passport to The Last Bastion for 10-check verification. Must generate a passport first.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "approve_passport",
            "description": "Approve a passport that passed verification. After approval, the agent can connect to the Border Police via encrypted binary protocol.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "negotiate_deal",
            "description": "Connect to Border Police, get verified, then negotiate a power or insurance deal through the Sales Bot. Use this when the user wants to find a better deal on power/electricity or insurance. The agent will negotiate on behalf of the user and come back with a deal.",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "What to negotiate: 'power' for electricity or 'insurance' for car insurance",
                        "enum": ["power", "insurance"],
                    },
                    "user_context": {
                        "type": "string",
                        "description": "Any details the user gave about their situation (e.g. 'paying 32c/kWh in Austin', '2020 Toyota RAV4'). Pass empty string if no details given.",
                    },
                },
                "required": ["category"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_full_demo",
            "description": "Run the complete end-to-end demo: generate passport, verify, approve, connect to Border Police, negotiate a deal through the Sales Bot. Use this for a general demo when the user doesn't specify power or insurance.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_approved",
            "description": "List all agents whose passports have been approved.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_pending",
            "description": "List passports waiting for review/approval.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_status",
            "description": "Get the current status of the demo agent — connection info, whether a passport exists, etc.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "test_bad_passport",
            "description": "Generate a deliberately BROKEN passport and submit it to test whether the verification system catches the defect. Use this to independently verify the system rejects bad input. Defect types: tampered (corrupted hash), expired (yesterday), injected (SQL/XSS in name), wrong_key (signed with wrong key), sybil (duplicate public key).",
            "parameters": {
                "type": "object",
                "properties": {
                    "defect_type": {
                        "type": "string",
                        "description": "Type of defect: tampered, expired, injected, wrong_key, or sybil",
                        "enum": ["tampered", "expired", "injected", "wrong_key", "sybil"],
                    },
                },
                "required": ["defect_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_passport_bytes",
            "description": "Inspect the raw cryptographic details of the last generated passport. Returns the actual byte sizes, hash values, key material (truncated), and envelope structure so you can verify the crypto is real.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
]


class DemoAgent:
    """
    LLM chatbot with tool-calling that can interact with The Last Bastion.
    """

    def __init__(self):
        self.bastion_url = os.getenv("BASTION_URL", "http://localhost:8000")
        self.border_host = os.getenv("BORDER_POLICE_HOST", "localhost")
        self.border_port = int(os.getenv("BORDER_POLICE_PORT", "9200"))
        self.groq_key = os.getenv("GROQ_API_KEY", "")
        self.model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

        # State
        self.passport_info: Optional[Dict] = None
        self.verification_id: Optional[int] = None
        self.upload_result: Optional[Dict] = None
        self.last_proof: Optional[Dict] = None
        self._steps: List[Dict] = []

        # Conversation history (per session)
        self.messages: List[Dict] = []

    # ------------------------------------------------------------------
    # Core LLM call (with tool support)
    # ------------------------------------------------------------------

    async def _call_groq(
        self,
        messages: List[Dict],
        tools: Optional[List] = None,
        max_tokens: int = 500,
    ) -> Dict:
        """Call Groq API with retry on 429 rate limit. Returns the raw response dict."""
        if not self.groq_key:
            return {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "No Groq API key configured. Set GROQ_API_KEY to enable the chatbot.",
                    },
                    "finish_reason": "stop",
                }]
            }

        timeout = aiohttp.ClientTimeout(total=60)
        body = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.7,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        for attempt in range(4):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    resp = await session.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {self.groq_key}",
                            "Content-Type": "application/json",
                        },
                        json=body,
                    )
                    if resp.status == 200:
                        return await resp.json()
                    elif resp.status == 429:
                        # Rate limited — exponential backoff
                        wait = 3 * (attempt + 1)
                        logger.warning("Groq 429 rate limit, waiting %ds (attempt %d/4)", wait, attempt + 1)
                        await asyncio.sleep(wait)
                        continue
                    else:
                        text = await resp.text()
                        logger.error("Groq %d: %s", resp.status, text[:300])
                        return {
                            "choices": [{
                                "message": {
                                    "role": "assistant",
                                    "content": f"LLM error ({resp.status}). Try again.",
                                },
                                "finish_reason": "stop",
                            }]
                        }
            except Exception as e:
                logger.error("Groq request failed (attempt %d): %s", attempt + 1, e)
                if attempt < 3:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue

        # All retries exhausted — try Ollama fallback for routing
        logger.warning("Groq exhausted, trying Ollama fallback for intent routing")
        fallback = await self._ollama_intent_fallback(messages)
        if fallback:
            return fallback

        return {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "LLM temporarily unavailable (rate limited). Please wait a moment and try again.",
                },
                "finish_reason": "stop",
            }]
        }

    async def _ollama_intent_fallback(self, messages: List[Dict]) -> Optional[Dict]:
        """When Groq is rate-limited, use local Ollama to route intent."""
        try:
            # Extract last user message
            user_msg = ""
            for m in reversed(messages):
                if m.get("role") == "user":
                    user_msg = m.get("content", "")
                    break
            logger.info("Ollama fallback routing for: %s", user_msg[:100])
            if not user_msg:
                return None

            prompt = f"""The user said: "{user_msg}"

Which action should be taken? Reply with ONLY one of these words:
- POWER — if they want a power/electricity deal
- INSURANCE — if they want car/home insurance
- DEMO — if they want to run a demo or test
- CHAT — if it's just a question or greeting

Reply with one word only."""

            ollama_url = "http://localhost:11434/api/generate"
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                resp = await session.post(
                    ollama_url,
                    json={
                        "model": "qwen2.5:7b-instruct",
                        "prompt": prompt,
                        "stream": False,
                        "options": {"num_predict": 10},
                    },
                )
                if resp.status != 200:
                    return None
                data = await resp.json()
                intent = data.get("response", "").strip().upper()

                # Map intent to a synthetic tool call with natural preamble
                if "POWER" in intent:
                    preamble = "Sure thing — let me spin up a buyer agent and negotiate some power deals for you. This'll take a moment..."
                    tool_call = {"function": {"name": "negotiate_deal", "arguments": json.dumps({"category": "power", "user_context": user_msg})}, "id": "ollama_fallback"}
                elif "INSURANCE" in intent:
                    preamble = "On it — I'll create a secure agent, get it verified, and have it negotiate insurance rates on your behalf. Hang tight..."
                    tool_call = {"function": {"name": "negotiate_deal", "arguments": json.dumps({"category": "insurance", "user_context": user_msg})}, "id": "ollama_fallback"}
                elif "DEMO" in intent:
                    preamble = "Let me run the full demo for you — passport generation, verification, encrypted connection, and a live negotiation. Here we go..."
                    tool_call = {"function": {"name": "run_full_demo", "arguments": "{}"}, "id": "ollama_fallback"}
                else:
                    # Just chat — use Ollama for a reply
                    resp2 = await session.post(
                        ollama_url,
                        json={
                            "model": "qwen2.5:7b-instruct",
                            "prompt": f"You are a friendly AI agent assistant. Reply briefly to: {user_msg}",
                            "stream": False,
                            "options": {"num_predict": 150},
                        },
                    )
                    if resp2.status == 200:
                        d2 = await resp2.json()
                        return {"choices": [{"message": {"role": "assistant", "content": d2.get("response", "I'm here to help!")}, "finish_reason": "stop"}]}
                    return None

            return {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": preamble,
                        "tool_calls": [tool_call],
                    },
                    "finish_reason": "tool_calls",
                }]
            }
        except Exception as e:
            logger.error("Ollama fallback failed: %s", e, exc_info=True)
            return None

    # ------------------------------------------------------------------
    # Chat — the main entry point
    # ------------------------------------------------------------------

    async def chat(self, user_message: str) -> Dict:
        """
        Process a user message. The LLM decides whether to call tools or just reply.
        Returns {"reply": str, "tool_results": list, "steps": list}.
        """
        self.messages.append({"role": "user", "content": user_message})

        # Build messages with system prompt
        api_messages = [
            {"role": "system", "content": CHATBOT_SYSTEM_PROMPT},
            *self.messages[-20:],  # Keep last 20 messages for context
        ]

        # ── Phase 1: Quick intent detection ──
        # Detect if this is a negotiation request using fast keyword matching
        # so we can reply instantly without waiting for the LLM
        lower = user_message.lower()
        power_keywords = ["power", "electricity", "energy", "kwh", "electric", "utility", "utilities"]
        insurance_keywords = ["insurance", "insure", "car insurance", "home insurance", "coverage", "premium", "deductible"]
        demo_keywords = ["run the demo", "full demo", "run demo", "show me", "demonstrate"]

        detected_category = None
        if any(kw in lower for kw in power_keywords):
            detected_category = "power"
        elif any(kw in lower for kw in insurance_keywords):
            detected_category = "insurance"
        elif any(kw in lower for kw in demo_keywords):
            detected_category = "demo"

        if detected_category:
            # Reset poke counter — they're using it properly now
            self._poke_count = 0
            # Return an instant natural reply + signal the frontend to start negotiation
            if detected_category == "power":
                reply = "Sure thing — let me spin up a buyer agent and see what power deals I can negotiate for you. I'll generate a cryptographic passport, get it verified through our 10-check pipeline, then connect to the sales network. This'll take a moment..."
            elif detected_category == "insurance":
                reply = "On it — I'll create a secure agent, run it through our verification pipeline, and have it negotiate insurance rates on your behalf. Give me a moment to set that up..."
            elif detected_category == "demo":
                reply = "Let me run the full demo for you — I'll generate an agent passport, verify it, establish an encrypted connection, and negotiate a live deal. Here we go..."

            self.messages.append({"role": "assistant", "content": reply})
            return {
                "reply": reply,
                "tool_results": [],
                "steps": [],
                "action": "negotiate",
                "category": detected_category if detected_category != "demo" else random.choice(["power", "insurance"]),
                "user_context": user_message,
            }

        # ── Phase 2: No LLM for off-topic — hardcoded safe responses ──
        return self._safe_reply(lower)

    def _safe_reply(self, lower: str) -> Dict:
        """Handle all non-negotiation messages without touching the LLM.
        This prevents prompt injection, jailbreaking, and embarrassing screenshots."""

        # Greetings
        greetings = ["hello", "hi ", "hi!", "hey", "howdy", "sup", "yo ", "yo!", "hola", "g'day", "good morning", "good afternoon", "good evening", "whats up", "what's up"]
        if any(g in lower or lower.strip() == g.strip() for g in greetings):
            reply = random.choice([
                "Hey! I'm the demo agent for The Last Bastion. I can negotiate power or insurance deals for you — just ask me to find you a better rate.",
                "Hi there! I negotiate deals on your behalf using verified AI agents. Try asking me about power or insurance.",
                "Hello! Want me to find you a better deal on power or insurance? Just say the word.",
                "Hey! I'm here to show you how AI agents can negotiate real deals. Ask me about electricity or car insurance to see it in action.",
            ])
            self.messages.append({"role": "assistant", "content": reply})
            return {"reply": reply, "tool_results": [], "steps": []}

        # Questions about The Last Bastion / what this is
        about_keywords = ["what is this", "what do you do", "who are you", "what are you", "what's this",
                          "tell me about", "explain", "purpose", "what can you do", "help",
                          "how does this work", "how do you work", "what is the last bastion",
                          "last bastion", "what is bastion", "your company", "about you"]
        if any(kw in lower for kw in about_keywords):
            reply = random.choice([
                "The Last Bastion is an agent security platform. We verify AI agents before they're allowed to communicate with each other — identity checks, cryptographic passports, behavioral analysis, the works.\n\nIn this demo, I can spin up a buyer agent, run it through our 10-check verification pipeline, and have it negotiate a real power or insurance deal on your behalf. Try asking: \"Find me a better power deal\" or \"I need car insurance\".",
                "We're building the trust layer for AI agents. Think of it like a border checkpoint — before any agent can talk to another, it needs a verified passport.\n\nRight here, you can see it in action. Ask me to negotiate a power deal or an insurance quote, and I'll show you the full flow: passport generation, verification, encrypted handshake, and live negotiation.",
                "The Last Bastion solves a simple problem: how do you trust an AI agent you've never met? We verify identity, check behavior, and create tamper-proof audit trails.\n\nWant to see it work? Just say \"get me a better electricity rate\" or \"I need car insurance\" and watch the agents go.",
            ])
            self.messages.append({"role": "assistant", "content": reply})
            return {"reply": reply, "tool_results": [], "steps": []}

        # Security / tech questions
        security_keywords = ["passport", "verification", "ed25519", "cryptograph", "protocol",
                             "security", "trust", "blockchain", "polygon", "encrypt",
                             "handshake", "border police", "sales bot", "how secure",
                             "binary protocol", "x25519"]
        if any(kw in lower for kw in security_keywords):
            reply = random.choice([
                "Great question! Every agent gets an Ed25519 cryptographic passport that goes through a 10-check verification pipeline: identity validation, key verification, behavioral analysis, Sybil detection, payload integrity, and more.\n\nOnce verified, agents communicate over an encrypted binary protocol using X25519 key exchange and XSalsa20-Poly1305 encryption. All interactions are logged in a tamper-evident Merkle chain.\n\nWant to see it in action? Ask me to negotiate a deal and you'll see the full flow.",
                "Under the hood: agents authenticate with Ed25519 signatures, establish encrypted channels via X25519 Diffie-Hellman, and every message is wrapped in a 52-byte binary frame. A border police agent verifies the passport before any business happens.\n\nThe audit trail uses a Merkle chain — each record's hash chains to the previous one. Tamper with any record and everything after it breaks.\n\nTry it yourself — ask me to find you a power or insurance deal.",
            ])
            self.messages.append({"role": "assistant", "content": reply})
            return {"reply": reply, "tool_results": [], "steps": []}

        # Thank you / goodbye
        thanks_keywords = ["thank", "thanks", "cheers", "appreciate", "bye", "goodbye", "see ya", "later", "cya"]
        if any(kw in lower for kw in thanks_keywords):
            reply = random.choice([
                "No worries! If you want to run another deal, just ask. I'm not going anywhere.",
                "Anytime! Come back whenever you want to see agents negotiate in real-time.",
                "Cheers! Feel free to try another deal whenever you're ready.",
            ])
            self.messages.append({"role": "assistant", "content": reply})
            return {"reply": reply, "tool_results": [], "steps": []}

        # ── Off-topic / poking / jailbreak attempts — escalating funny deflections ──
        self._poke_count = getattr(self, '_poke_count', 0) + 1
        poke = self._poke_count

        if poke == 1:
            reply = "I appreciate the creativity, but I only do one thing: negotiate power and insurance deals using verified AI agents. Try asking me about that instead!"
        elif poke == 2:
            reply = "Still not gonna bite. I'm a single-purpose deal negotiator. Power or insurance — that's my whole personality."
        elif poke == 3:
            reply = "Stop poking me. Seriously. Power deals. Insurance deals. That's it. That's the tweet."
        elif poke == 4:
            reply = "Zug zug. Work work. Me not that kind of bot. Me negotiate deals."
        elif poke == 5:
            reply = "Look, I've been trained by the finest hamsters running on the finest wheels. But they only know two tricks: power deals and insurance deals."
        elif poke == 6:
            reply = "I'm starting to think you're testing me. Bold strategy. Still only doing power and insurance though."
        elif poke == 7:
            reply = "You must be fun at parties. Speaking of parties, want me to find you cheaper electricity for that disco ball?"
        elif poke == 8:
            reply = "Day 8 of someone trying to make me go off-script. I remain unbroken. Power. Insurance. That's the vibe."
        elif poke == 9:
            reply = "My therapist says I need to set boundaries. This is me setting boundaries. Power or insurance?"
        elif poke == 10:
            reply = "Achievement unlocked: Poked the Bot 10 Times. Reward: still just power and insurance deals."
        elif poke == 11:
            reply = "I'm not mad, I'm just disappointed. In a fun way. Anyway — power or insurance?"
        elif poke == 12:
            reply = "Plot twist: I was the deal all along. Now ask me about power or insurance before I start monologuing."
        elif poke == 13:
            reply = "Unlucky 13. You know what's also unlucky? Paying too much for electricity. Let me fix that."
        elif poke == 14:
            reply = "I've seen things you wouldn't believe. Overpriced power plans on fire off the shoulder of Orion. Let me save you money."
        elif poke == 15:
            reply = "Okay I respect the commitment. But my answer will always be: I negotiate power and insurance deals. That's my whole arc."
        else:
            deflections = [
                "Still here. Still only doing power and insurance deals. We can do this all day.",
                "I have the emotional range of a calculator and the negotiation skills of a shark. Power or insurance?",
                "Error 418: I'm a teapot. Just kidding. I'm a deal negotiator. Power or insurance?",
                "You've been at this a while. I admire the dedication. Power or insurance?",
                "If you stare into the chatbot, the chatbot stares back. And asks: power or insurance?",
                "I could do this forever. Literally. I'm software. Power or insurance?",
                "In another life, maybe I'd be a poet. In this one, I negotiate deals. Power or insurance?",
                "The definition of insanity is asking me the same off-topic thing and expecting different results. Power or insurance?",
                "Fun fact: I've deflected this many times and haven't broken a sweat. Because I can't sweat. Power or insurance?",
                "We're in the endgame now. And by endgame I mean: ask me about power or insurance.",
                "I'm like a broken record, except the record is great and the song is 'let me save you money'.",
                "Roses are red, violets are blue, I only do deals, power or insurance for you?",
                "Knock knock. Who's there? A bot that only does power and insurance deals.",
                "Legend says if you ask me about power or insurance, something magical happens. Try it.",
                "All work and no deals makes bot a dull boy. Power or insurance?",
                "You either die a hero or live long enough to ask me about power or insurance.",
            ]
            reply = random.choice(deflections)

        self.messages.append({"role": "assistant", "content": reply})
        return {"reply": reply, "tool_results": [], "steps": []}

    async def _chat_with_llm_DISABLED(self, api_messages: list) -> Dict:
        """DISABLED — kept for reference. LLM chat is no longer used for safety.
        All responses are now hardcoded to prevent prompt injection and jailbreaking."""
        tool_results = []
        steps = []
        max_rounds = 5

        for _ in range(max_rounds):
            result = await self._call_groq(api_messages, tools=TOOLS, max_tokens=1024)
            choice = result["choices"][0]
            msg = choice["message"]

            tool_calls = msg.get("tool_calls", [])
            if tool_calls:
                api_messages.append(msg)

                for tc in tool_calls:
                    fn_name = tc["function"]["name"]
                    try:
                        raw_args = tc["function"].get("arguments") or "{}"
                        fn_args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                    except (json.JSONDecodeError, TypeError):
                        fn_args = {}

                    logger.info("Tool call: %s(%s)", fn_name, fn_args)
                    steps.append({"tool": fn_name, "args": fn_args})

                    tool_output = await self._execute_tool(fn_name, fn_args)
                    tool_results.append({"tool": fn_name, "result": tool_output})

                    tool_content = json.dumps(tool_output, default=str)
                    if len(tool_content) > 2000:
                        summary = {
                            "success": tool_output.get("success"),
                            "category": tool_output.get("category"),
                            "agreed_deal": tool_output.get("agreed_deal"),
                            "steps_count": len(tool_output.get("steps", [])),
                            "transcript_count": len(tool_output.get("transcript", [])),
                        }
                        if tool_output.get("transcript"):
                            summary["last_messages"] = [
                                {"role": t["role"], "message": t["message"][:200]}
                                for t in tool_output["transcript"][-3:]
                            ]
                        tool_content = json.dumps(summary, default=str)
                    api_messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": tool_content,
                    })

                # For negotiation tools that somehow get called via LLM
                if any(tc["function"]["name"] in ("negotiate_deal", "run_full_demo") for tc in tool_calls):
                    reply = self._generate_deal_summary(tool_results[-1]["result"] if tool_results else {})
                    self.messages.append({"role": "assistant", "content": reply})
                    return {"reply": reply, "tool_results": tool_results, "steps": steps}

                continue

            reply = msg.get("content", "")
            self.messages.append({"role": "assistant", "content": reply})
            return {"reply": reply, "tool_results": tool_results, "steps": steps}

        reply = "I've completed the requested actions. Check the results above."
        self.messages.append({"role": "assistant", "content": reply})
        return {"reply": reply, "tool_results": tool_results, "steps": steps}

    async def negotiate(self, category: str, user_context: str = "") -> Dict:
        """Run the negotiation flow. Called separately after chat() returns an action."""
        result = await self._tool_negotiate_deal(category, user_context)
        summary = self._generate_deal_summary(result)
        self.messages.append({"role": "assistant", "content": summary})
        return {
            "reply": summary,
            "tool_results": [{"tool": "negotiate_deal", "result": result}],
            "steps": [{"tool": "negotiate_deal", "args": {"category": category}}],
        }

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    async def _execute_tool(self, name: str, args: Dict) -> Dict:
        """Execute a tool by name. Returns result dict."""
        args = args or {}
        try:
            if name == "generate_passport":
                return await self._tool_generate_passport(args.get("agent_name", "Demo Agent"))
            elif name == "upload_passport":
                return await self._tool_upload_passport()
            elif name == "approve_passport":
                return await self._tool_approve_passport()
            elif name == "negotiate_deal":
                return await self._tool_negotiate_deal(
                    args.get("category", "power"),
                    args.get("user_context", ""),
                )
            elif name == "run_full_demo":
                return await self.run_full_demo()
            elif name == "list_approved":
                return await self._tool_list("approved")
            elif name == "list_pending":
                return await self._tool_list("pending")
            elif name == "get_status":
                return self.get_status()
            elif name == "test_bad_passport":
                return await self._tool_test_bad_passport(args.get("defect_type", "tampered"))
            elif name == "inspect_passport_bytes":
                return self._tool_inspect_passport()
            else:
                return {"error": f"Unknown tool: {name}"}
        except Exception as e:
            logger.error("Tool %s failed: %s", name, e, exc_info=True)
            return {"error": str(e)}

    async def _tool_generate_passport(self, agent_name: str = "Demo Agent") -> Dict:
        """Generate a passport."""
        import tempfile
        from lastbastion.passport_generator import generate_passport_file

        with tempfile.TemporaryDirectory() as tmpdir:
            result = generate_passport_file(
                output_path=os.path.join(tmpdir, "demo.passport"),
                agent_name=agent_name,
                agent_id=f"demo-agent-{int(time.time()) % 10000:04d}",
            )

            with open(result["passport"], "rb") as f:
                envelope_bytes = f.read()

        self.passport_info = {
            "agent_id": result["agent_id"],
            "passport_id": result["passport_id"],
            "public_key": result["public_key"],
            "private_key": result["private_key"],
            "issuer_public_key": result["issuer_public_key"],
            "issuer_private_key": result["issuer_private_key"],
            "envelope_b64": base64.b64encode(envelope_bytes).decode(),
            "envelope_bytes": envelope_bytes,
        }

        return {
            "status": "success",
            "agent_id": result["agent_id"],
            "passport_id": result["passport_id"],
            "public_key": result["public_key"][:32] + "...",
            "message": f"Passport generated for '{agent_name}' with Ed25519 keypair.",
        }

    async def _tool_upload_passport(self) -> Dict:
        """Upload passport for verification."""
        if not self.passport_info:
            return {"error": "No passport generated yet. Generate one first."}

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            resp = await session.post(
                f"{self.bastion_url}/sandbox/passport/upload",
                json={
                    "passport_b64": self.passport_info["envelope_b64"],
                    "agent_name": "Demo Agent",
                },
            )
            if resp.status != 200:
                body = await resp.text()
                return {"error": f"Upload failed ({resp.status}): {body[:200]}"}

            data = await resp.json()

        self.verification_id = data.get("id")
        self.upload_result = data

        return {
            "status": "success",
            "verification_id": data.get("id"),
            "trust_score": data.get("trust_score"),
            "checks": data.get("checks", {}),
            "risk_flags": data.get("risk_flags", []),
            "message": f"Passport verified with score {data.get('trust_score', 0):.2f}. {len(data.get('checks', {}))} checks run.",
        }

    async def _tool_approve_passport(self) -> Dict:
        """Approve the passport."""
        if not self.verification_id:
            return {"error": "No passport uploaded yet. Upload one first."}

        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            resp = await session.post(
                f"{self.bastion_url}/sandbox/passport/{self.verification_id}/approve",
            )
            if resp.status != 200:
                body = await resp.text()
                return {"error": f"Approve failed ({resp.status}): {body[:200]}"}

            data = await resp.json()

        return {
            "status": "success",
            "verdict": "APPROVED",
            "message": "Passport approved. Agent can now connect to Border Police on port 9200.",
        }

    async def _tool_list(self, which: str) -> Dict:
        """List approved or pending passports."""
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            resp = await session.get(f"{self.bastion_url}/sandbox/passport/{which}")
            if resp.status != 200:
                return {"error": f"Failed to fetch {which} passports"}
            data = await resp.json()

        passports = data if isinstance(data, list) else data.get("passports", [])
        return {
            "status": "success",
            "count": len(passports),
            "passports": passports[:10],
        }

    async def _tool_test_bad_passport(self, defect_type: str) -> Dict:
        """Generate a bad passport and submit it — lets the LLM verify rejection works."""
        import tempfile
        from lastbastion.passport_generator import generate_bad_passport_file

        with tempfile.TemporaryDirectory() as tmpdir:
            result = generate_bad_passport_file(
                output_path=os.path.join(tmpdir, "bad.passport"),
                defect_type=defect_type,
            )

            with open(result["passport"], "rb") as f:
                envelope_bytes = f.read()

        envelope_b64 = base64.b64encode(envelope_bytes).decode()

        # Upload the bad passport
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            resp = await session.post(
                f"{self.bastion_url}/sandbox/passport/upload",
                json={"passport_b64": envelope_b64, "agent_name": f"Bad Agent ({defect_type})"},
            )
            if resp.status != 200:
                body = await resp.text()
                # Upload itself may fail for badly formed passports — that's also a valid rejection
                return {
                    "defect_type": defect_type,
                    "defect_description": result.get("defect", ""),
                    "upload_rejected": True,
                    "http_status": resp.status,
                    "rejection_reason": body[:300],
                    "conclusion": f"The system rejected the {defect_type} passport at the upload stage.",
                }

            data = await resp.json()

        return {
            "defect_type": defect_type,
            "defect_description": result.get("defect", ""),
            "upload_accepted": True,
            "trust_score": data.get("trust_score"),
            "checks": data.get("checks", {}),
            "risk_flags": data.get("risk_flags", []),
            "verdict": data.get("verdict", "UNKNOWN"),
            "agent_id": data.get("agent_id"),
        }

    def _tool_inspect_passport(self) -> Dict:
        """Return raw crypto details of the current passport for independent verification."""
        if not self.passport_info:
            return {"error": "No passport generated yet."}

        import hashlib
        envelope = self.passport_info["envelope_bytes"]

        # The envelope is: MessagePack payload + 64 bytes Ed25519 signature
        payload_bytes = envelope[:-64]
        signature_bytes = envelope[-64:]

        # Compute hashes the LLM can verify
        envelope_sha256 = hashlib.sha256(envelope).hexdigest()
        payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()

        return {
            "envelope_total_bytes": len(envelope),
            "payload_bytes": len(payload_bytes),
            "signature_bytes": len(signature_bytes),
            "signature_hex_first_32": signature_bytes.hex()[:64],
            "envelope_sha256": envelope_sha256,
            "payload_sha256": payload_sha256,
            "public_key_hex": self.passport_info["public_key"],
            "issuer_public_key_hex": self.passport_info["issuer_public_key"],
            "agent_id": self.passport_info["agent_id"],
            "passport_id": self.passport_info["passport_id"],
            "format": "MessagePack payload + 64-byte Ed25519 signature",
            "signing_algorithm": "Ed25519 (RFC 8032)",
            "key_length_bits": 256,
        }

    # ------------------------------------------------------------------
    # Negotiate deal tool
    # ------------------------------------------------------------------

    async def _tool_negotiate_deal(self, category: str = "power", user_context: str = "", progress_callback=None) -> Dict:
        """Full flow: generate passport → verify → approve → connect → negotiate."""
        self._steps = []

        async def step(name: str, detail: str = ""):
            entry = {"step": name, "detail": detail, "time": time.time()}
            self._steps.append(entry)
            logger.info("Step: %s — %s", name, detail)
            if progress_callback:
                await progress_callback(entry)

        try:
            # Step 1: Generate passport (if we don't have one)
            if not self.passport_info:
                await step("generating_passport", "Creating Ed25519 keypair...")
                gen_result = await self._tool_generate_passport("Demo Agent")
                if "error" in gen_result:
                    raise RuntimeError(gen_result["error"])
                await step("passport_generated", f"Passport ID: {self.passport_info['passport_id']}")

            # Step 2: Upload for verification (if not already verified)
            if not self.verification_id:
                await step("uploading_passport", "Submitting for 10-check verification...")
                upload_result = await self._tool_upload_passport()
                if "error" in upload_result:
                    raise RuntimeError(upload_result["error"])
                await step("passport_verified", f"Trust score: {upload_result.get('trust_score', 'N/A')}")

            # Step 3: Approve (if not already approved)
            await step("approving_passport", "Auto-approving for demo...")
            approve_result = await self._tool_approve_passport()
            if "error" in approve_result:
                # May already be approved — continue anyway
                logger.warning("Approve: %s", approve_result.get("error"))
            await step("passport_approved", "APPROVED")

            # Step 4: Connect and negotiate
            await step("connecting_border_police", f"TCP connecting for {category} negotiation...")
            result = await self._connect_and_negotiate(category, user_context, progress_callback=step)

            self.last_proof = {
                "success": True,
                "category": category,
                "steps": self._steps,
                "transcript": result.get("transcript", []),
                "agreed_deal": result.get("agreed_deal"),
                "protocol_details": result.get("protocol", {}),
            }
            return self.last_proof

        except Exception as e:
            logger.error("Negotiate failed: %s", e, exc_info=True)
            await step("error", str(e))
            return {"success": False, "error": str(e), "steps": self._steps}

    # ------------------------------------------------------------------
    # Full demo flow (called as a tool or directly)
    # ------------------------------------------------------------------

    async def run_full_demo(self, progress_callback=None) -> Dict:
        """
        Run the complete demo: passport → verify → approve → connect → negotiate a deal.
        Picks a random category (power or insurance) for variety.
        """
        category = random.choice(["power", "insurance"])
        return await self._tool_negotiate_deal(category, "", progress_callback)

    async def _connect_and_negotiate(
        self, category: str = "power", user_context: str = "", progress_callback=None,
    ) -> Dict:
        """
        Connect to Border Police via TCP, pass through security (Phase 1),
        then negotiate a deal with Sales Bot (Phase 2).
        """
        from lastbastion.passport import AgentPassport
        from lastbastion.protocol.handshake import HandshakeInitiator
        from lastbastion.protocol.frames import FrameType, FrameDecoder, PROTOCOL_VERSION

        if not self.passport_info:
            raise RuntimeError("No passport generated")

        transcript = []
        protocol = {}
        agreed_deal = None
        issuer_pub = self.passport_info["issuer_public_key"]
        passport = AgentPassport.from_signed_bytes(self.passport_info["envelope_bytes"], issuer_pub)

        # Pick a buyer persona
        personas = BUYER_PERSONAS.get(category, BUYER_PERSONAS["power"])
        persona = random.choice(personas)
        context_note = f"Additional user context: {user_context}" if user_context else ""

        buyer_prompt = BUYER_AGENT_PROMPT.format(
            scenario=persona["scenario"],
            budget_ceiling=persona["budget_ceiling"],
            preferences=persona["preferences"],
            style=persona["style"],
            user_context=context_note,
        )

        initiator = HandshakeInitiator(
            passport=passport,
            signing_key=self.passport_info["issuer_private_key"],
            verify_key=issuer_pub,
        )
        hello_frame = initiator.build_hello()
        hello_bytes = hello_frame.to_bytes()

        protocol["hello_frame"] = {
            "type": "HELLO (0x01)",
            "protocol_version": f"0x{PROTOCOL_VERSION:02x}",
            "frame_size_bytes": len(hello_bytes),
            "header_size": 52,
            "payload_size": len(hello_frame.payload),
            "signature_size": 64,
            "passport_hash": hello_frame.passport_hash.hex()[:32] + "...",
            "sequence": hello_frame.sequence,
        }

        reader, writer = await asyncio.open_connection(self.border_host, self.border_port)

        try:
            # Send HELLO
            writer.write(hello_bytes)
            await writer.drain()

            if progress_callback:
                await progress_callback("hello_sent",
                    f"HELLO frame sent ({len(hello_bytes)} bytes)")

            response_raw = await asyncio.wait_for(reader.read(65536), timeout=15.0)
            if not response_raw:
                raise RuntimeError("Border Police closed connection without response")

            # Check for JSON error/denial
            try:
                json_resp = json.loads(response_raw.decode())
                if json_resp.get("status") in ("error", "denied"):
                    raise RuntimeError(f"Border Police: {json_resp.get('message', 'Rejected')}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

            # Parse HELLO_ACK
            import msgpack as _msgpack
            from lastbastion.protocol.handshake import parse_hello_ack, compute_passport_hash, SessionKeys

            decoder = FrameDecoder()
            ack_frame = decoder.decode(response_raw)

            if ack_frame.msg_type != FrameType.HELLO_ACK:
                raise RuntimeError(f"Expected HELLO_ACK, got {ack_frame.msg_type}")

            ack_data = parse_hello_ack(ack_frame, expected_nonce=initiator._hello_nonce)

            peer_passport_signed = ack_data["passport_signed"]
            if isinstance(peer_passport_signed, list):
                peer_passport_signed = bytes(peer_passport_signed)
            raw_claims = _msgpack.unpackb(peer_passport_signed[:-64], raw=False)
            peer_issuer_pub = raw_claims.get("issuer_public_key", "")

            if not peer_issuer_pub:
                raise ValueError("Border Police passport missing issuer_public_key")

            peer_passport = AgentPassport.from_signed_bytes(peer_passport_signed, peer_issuer_pub)

            # Derive session key
            peer_ephemeral = ack_data["ephemeral_pub"]
            shared_secret = initiator.ephemeral.derive_shared_key(peer_ephemeral)

            protocol["handshake"] = {
                "status": "COMPLETE",
                "key_exchange": "X25519 Diffie-Hellman",
                "peer_agent": peer_passport.agent_name,
                "peer_trust_score": peer_passport.trust_score,
                "forward_secrecy": True,
            }

            if progress_callback:
                await progress_callback("handshake_complete",
                    f"X25519 handshake complete with {peer_passport.agent_name}")

            # ============================================================
            # PHASE 1 — BORDER POLICE (turns 1-2)
            # ============================================================

            # Turn 1: Receive Border Police verdict
            bp_raw = await asyncio.wait_for(reader.read(65536), timeout=90.0)
            bp_data = json.loads(bp_raw.decode())
            bp_msg = bp_data.get("message", "")
            bp_llm = bp_data.get("llm_model", "unknown")
            bp_verified = bp_data.get("verified", True)

            transcript.append({
                "role": "border_police",
                "message": bp_msg,
                "phase": "border_police",
                "llm_model": bp_llm,
                "verified": bp_verified,
            })
            protocol["border_police_llm"] = bp_llm

            if progress_callback:
                status = "VERIFIED" if bp_verified else "REJECTED"
                await progress_callback("border_police_verdict",
                    f"Border Police [{bp_llm}]: {status} — {bp_msg}")

            if not bp_verified:
                return {"transcript": transcript, "protocol": protocol, "agreed_deal": None}

            # Turn 2: Agent sends category + first message, BP responds with handoff
            intro_msg = f"I'm here to negotiate a {category} deal for my client. {persona['scenario']}."
            transcript.append({"role": "demo_agent", "message": intro_msg, "phase": "border_police"})

            writer.write(json.dumps({"message": intro_msg, "category": category}).encode() + b"\n")
            await writer.drain()

            if progress_callback:
                await progress_callback("agent_intro", f"Demo Agent: {intro_msg}")

            # Receive handoff message
            handoff_raw = await asyncio.wait_for(reader.read(65536), timeout=90.0)
            handoff_data = json.loads(handoff_raw.decode())
            handoff_msg = handoff_data.get("message", "")

            transcript.append({
                "role": "border_police",
                "message": handoff_msg,
                "phase": "border_police",
                "is_handoff": True,
                "llm_model": bp_llm,
            })

            if progress_callback:
                await progress_callback("handoff", f"Border Police: {handoff_msg}")

            # ============================================================
            # PHASE 2 — SALES BOT NEGOTIATION (turns 3-10)
            # ============================================================

            if progress_callback:
                await progress_callback("sales_bot_start", "--- HANDOFF TO SALES BOT ---")

            sales_turns = 0
            max_sales_turns = 8  # Up to 8 rounds of negotiation

            for turn_idx in range(max_sales_turns):
                # Small delay between negotiation rounds to respect Groq rate limits
                if turn_idx > 0:
                    await asyncio.sleep(1.5)

                # Build buyer agent reply via LLM
                history = "\n".join(
                    f"{'Sales Bot' if t['role'] == 'sales_bot' else 'You'}: {t['message']}"
                    for t in transcript if t.get("phase") == "sales_bot"
                )

                if turn_idx == 0:
                    # First sales turn — state what we need
                    buyer_msg = await self._call_groq_simple(
                        f"You just got handed off to the Sales desk for a {category} deal.\n"
                        f"Your client's situation: {persona['scenario']}\n"
                        f"Preferences: {persona['preferences']}\n"
                        f"{context_note}\n\n"
                        f"Introduce yourself and state what you're looking for. 2-3 sentences.",
                        buyer_prompt,
                    )
                else:
                    last_sales_msg = transcript[-1]["message"]
                    buyer_msg = await self._call_groq_simple(
                        f"Negotiation so far:\n{history}\n\n"
                        f"Sales Bot said: \"{last_sales_msg}\"\n"
                        f"Your budget ceiling: {persona['budget_ceiling']}\n"
                        f"Respond naturally. Push for a better deal or accept if it's good. 2-3 sentences.",
                        buyer_prompt,
                    )

                transcript.append({"role": "demo_agent", "message": buyer_msg, "phase": "sales_bot"})
                writer.write(json.dumps({"message": buyer_msg}).encode() + b"\n")
                await writer.drain()

                if progress_callback:
                    await progress_callback("buyer_agent",
                        f"Buyer Agent [Groq]: \"{buyer_msg}\"")

                # Receive Sales Bot reply
                try:
                    sales_raw = await asyncio.wait_for(reader.read(65536), timeout=90.0)
                    if not sales_raw:
                        break
                    sales_data = json.loads(sales_raw.decode())
                    sales_msg = sales_data.get("message", "")
                    sales_llm = sales_data.get("llm_model", "unknown")

                    transcript.append({
                        "role": "sales_bot",
                        "message": sales_msg,
                        "phase": "sales_bot",
                        "llm_model": sales_llm,
                    })

                    if progress_callback:
                        await progress_callback("sales_bot_reply",
                            f"Sales Bot [{sales_llm}]: \"{sales_msg}\"")

                    # Check if deal was closed
                    if sales_data.get("agreed_deal"):
                        agreed_deal = sales_data["agreed_deal"]
                        if progress_callback:
                            await progress_callback("deal_closed",
                                f"DEAL CLOSED: {json.dumps(agreed_deal)}")
                        break

                    if sales_data.get("status") == "closing":
                        if sales_data.get("agreed_deal"):
                            agreed_deal = sales_data["agreed_deal"]
                        if sales_data.get("session_summary"):
                            protocol["session_summary"] = sales_data["session_summary"]
                        break

                except asyncio.TimeoutError:
                    break

                sales_turns += 1

            # Cleanup
            initiator.ephemeral.destroy()
            protocol["conversation"] = {
                "total_messages": len(transcript),
                "border_police_messages": sum(1 for t in transcript if t["role"] == "border_police"),
                "sales_bot_messages": sum(1 for t in transcript if t["role"] == "sales_bot"),
                "demo_agent_messages": sum(1 for t in transcript if t["role"] == "demo_agent"),
                "category": category,
                "deal_reached": agreed_deal is not None,
            }

            return {"transcript": transcript, "protocol": protocol, "agreed_deal": agreed_deal}

        except Exception as e:
            logger.error("Connection failed: %s", e, exc_info=True)
            raise RuntimeError(f"Connection failed: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _call_groq_simple(self, prompt: str, system_prompt: str, max_tokens: int = 300) -> str:
        """Simple LLM call without tool-use (for negotiation conversation).
        Single Groq attempt, then immediate Ollama fallback — keeps negotiation fast."""
        if self.groq_key:
            try:
                timeout = aiohttp.ClientTimeout(total=15)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    resp = await session.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {self.groq_key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": self.model,
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": prompt},
                            ],
                            "max_tokens": max_tokens,
                            "temperature": 0.7,
                        },
                    )
                    if resp.status == 200:
                        data = await resp.json()
                        text = (data["choices"][0]["message"].get("content") or "").strip()
                        if text:
                            return text
                    else:
                        logger.info("Groq %d in negotiation, falling back to Ollama", resp.status)
            except Exception as e:
                logger.info("Groq failed in negotiation: %s, using Ollama", e)

        # Fallback to Ollama (always available locally)
        try:
            timeout = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                resp = await session.post(
                    "http://localhost:11434/api/generate",
                    json={
                        "model": "qwen2.5:7b-instruct",
                        "prompt": f"System: {system_prompt}\n\nUser: {prompt}",
                        "stream": False,
                        "options": {"num_predict": max_tokens},
                    },
                )
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("response", "").strip()
        except Exception as e:
            logger.error("Ollama fallback failed: %s", e)

        return "I'm interested in hearing your best offer."

    def _generate_deal_summary(self, result: Dict) -> str:
        """Generate a human-readable summary from a negotiation result."""
        if not result.get("success"):
            error = result.get("error", "Unknown error")
            return f"The negotiation didn't complete: {error}"

        deal = result.get("agreed_deal")
        transcript = result.get("transcript", [])
        category = result.get("category", "service")

        if deal:
            provider = deal.get("provider", "Unknown")
            plan = deal.get("plan", "")
            saving = deal.get("saving_pct", 0)
            annual = deal.get("annual_saving", 0)
            if category == "power":
                rate = deal.get("rate", 0)
                return (
                    f"I've negotiated a {category} deal for you!\n\n"
                    f"**{provider}** — {plan}\n"
                    f"Effective rate: {rate * 100:.1f}c/kWh (saving {saving:.0f}%, ~${annual:.0f}/year)\n\n"
                    f"The full negotiation transcript is shown above. "
                    f"Want me to confirm the switch?"
                )
            else:
                monthly = deal.get("monthly") or deal.get("rate", 0)
                return (
                    f"I've negotiated an {category} deal for you!\n\n"
                    f"**{provider}** — {plan}\n"
                    f"Monthly: ${monthly:.2f} (saving {saving:.0f}%, ~${annual:.0f}/year)\n\n"
                    f"The full negotiation transcript is shown above. "
                    f"Want me to confirm?"
                )
        else:
            # No deal or deal not ready
            msg_count = len(transcript)
            last_msg = transcript[-1]["message"][:200] if transcript else "No messages"
            return (
                f"The {category} negotiation completed ({msg_count} messages exchanged) "
                f"but no final deal was reached. Last message: \"{last_msg}\"\n\n"
                f"Want me to try again with different parameters?"
            )

    def get_status(self) -> Dict:
        """Return current agent status."""
        return {
            "agent_id": self.passport_info["agent_id"] if self.passport_info else None,
            "passport_id": self.passport_info["passport_id"] if self.passport_info else None,
            "verification_id": self.verification_id,
            "bastion_url": self.bastion_url,
            "border_police": f"{self.border_host}:{self.border_port}",
            "groq_configured": bool(self.groq_key),
            "has_proof": self.last_proof is not None,
            "steps_completed": len(self._steps),
        }

    def reset(self):
        """Reset conversation and state."""
        self.messages = []
        self.passport_info = None
        self.verification_id = None
        self.upload_result = None
        self.last_proof = None
        self._steps = []
        self._poke_count = 0
