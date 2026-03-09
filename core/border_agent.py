"""
Border Police Agent — the gatekeeper at The Last Bastion's front door.

Two-phase architecture behind one TCP connection:
  Phase 1 — BORDER POLICE (turns 1-2): Quick security gate. Verify or reject.
  Phase 2 — SALES BOT (turns 3-10): Negotiates real-world deals (power, insurance)
            with visiting agents. Returns structured agreement.

The LLM does NOT make security decisions — those are hardcoded crypto checks.
The LLMs ARE the personalities: Border Police is the bouncer, Sales Bot is the dealmaker.
"""

import asyncio
import json
import logging
import os
import re
import time
from typing import Dict, List, Optional

import aiohttp

from lastbastion.crypto import generate_keypair
from lastbastion.passport import AgentPassport
from lastbastion.protocol.frames import (
    BastionFrame,
    FrameType,
    FrameEncoder,
    FrameDecoder,
    serialize_payload,
    deserialize_payload,
    compute_passport_hash,
)
from lastbastion.protocol.handshake import (
    HandshakeResponder,
    parse_hello,
    SessionKeys,
)

logger = logging.getLogger("BorderPolice")

BORDER_POLICE_PORT = 9200

# Phase 1 (Border Police): 2 turns. Phase 2 (Sales Bot): up to 8 turns.
MAX_TURNS = 10
BORDER_POLICE_TURNS = 2  # BP handles turns 1-2, then hands off


# ---------------------------------------------------------------------------
# LLM caller — plain text mode (no JSON forcing)
# ---------------------------------------------------------------------------

async def _call_llm(prompt: str, system_prompt: str, max_tokens: int = 500) -> tuple:
    """
    Call the LLM in plain text mode (not JSON mode).
    Tries Groq first with retry on 429, falls back to Ollama.
    Returns (response_text, model_name) tuple.
    """
    from dotenv import load_dotenv
    load_dotenv()

    groq_key = os.getenv("GROQ_API_KEY", "")
    timeout = aiohttp.ClientTimeout(total=30)

    # Try Groq first (faster, smarter) — retry on 429 rate limit
    if groq_key:
        model_name = os.getenv("STRATEGIST_MODEL", "llama-3.3-70b-versatile")
        for attempt in range(3):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    resp = await session.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {groq_key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": model_name,
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": prompt},
                            ],
                            "max_tokens": max_tokens,
                            "temperature": 0.8,
                        },
                    )
                    if resp.status == 200:
                        data = await resp.json()
                        actual_model = data.get("model", model_name)
                        text = data["choices"][0]["message"]["content"].strip()
                        return text, f"{actual_model} (via Groq)"
                    elif resp.status == 429:
                        # Rate limited — wait with exponential backoff then retry
                        wait = 3 * (attempt + 1)
                        logger.warning("Groq 429 rate limit, waiting %ds (attempt %d/3)", wait, attempt + 1)
                        await asyncio.sleep(wait)
                        continue
                    else:
                        body = await resp.text()
                        logger.warning("Groq %d: %s", resp.status, body[:200])
                        break  # Non-retryable error, fall through to Ollama
            except Exception as e:
                logger.warning("Groq failed (attempt %d): %s", attempt + 1, e)
                if attempt < 2:
                    await asyncio.sleep(2)
                    continue
                break

    # Fallback: Ollama (local)
    ollama_url = os.getenv("LLM_URL", "http://localhost:11434/api/generate")
    model_name = os.getenv("LLM_MODEL", "qwen2.5:7b-instruct")
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as session:
            resp = await session.post(
                ollama_url,
                json={
                    "model": model_name,
                    "prompt": prompt,
                    "system": system_prompt,
                    "stream": False,
                },
            )
            if resp.status == 200:
                data = await resp.json()
                text = data.get("response", "").strip()
                return text, f"{model_name} (via Ollama, local)"
    except Exception as e:
        logger.warning("Ollama failed: %s", e)

    # Last resort — hardcoded fallback (LLM completely unavailable)
    return "", "none (fallback)"


# ---------------------------------------------------------------------------
# Provider catalog — realistic US pricing with real discount mechanics
# ---------------------------------------------------------------------------
# Modelled on how US power retailers and insurers actually price:
# - Power: base unit rate (c/kWh) + daily supply charge + usage tiers
#   Discounts: prompt payment, direct debit, dual fuel, loyalty, contract length
# - Insurance: base premium + excess trade-off + no-claims bonus
#   Discounts: multi-policy, alarm/immobiliser, low-km, age bracket, payment frequency

PROVIDER_CATALOG = {
    "power": [
        {
            "provider": "MegaEnergy",
            "tagline": "Largest retailer — strong on price, weak on service",
            "plans": [
                {
                    "name": "Anytime Fixed 12",
                    "rate_kwh": 0.289,        # base unit rate before discounts
                    "daily_supply_charge": 1.85,  # $/day (line + meter charge)
                    "contract_months": 12,
                    "green": False,
                    "low_user_rate": 0.265,    # first 600kWh/month (low-user tier)
                    "high_user_rate": 0.305,   # above 600kWh/month
                },
                {
                    "name": "Loyalty 24",
                    "rate_kwh": 0.259,
                    "daily_supply_charge": 1.72,
                    "contract_months": 24,
                    "green": False,
                    "low_user_rate": 0.239,
                    "high_user_rate": 0.279,
                },
                {
                    "name": "Flexi (No Contract)",
                    "rate_kwh": 0.319,
                    "daily_supply_charge": 2.10,
                    "contract_months": 0,
                    "green": False,
                },
            ],
            "discounts": {
                "prompt_payment": {"pct": 20, "condition": "pay within 14 days of invoice"},
                "direct_debit": {"pct": 3, "condition": "automatic payment from bank account"},
                "dual_fuel": {"pct": 5, "condition": "bundle gas + electricity"},
                "online_only": {"pct": 2, "condition": "paperless billing, manage account online"},
            },
        },
        {
            "provider": "EcoGreen Energy",
            "tagline": "100% renewable — certified carbonzero, premium positioning",
            "plans": [
                {
                    "name": "Pure Green 12",
                    "rate_kwh": 0.312,
                    "daily_supply_charge": 1.95,
                    "contract_months": 12,
                    "green": True,
                    "renewable_cert": "Green-e certified renewable",
                },
                {
                    "name": "Pure Green 24",
                    "rate_kwh": 0.285,
                    "daily_supply_charge": 1.78,
                    "contract_months": 24,
                    "green": True,
                    "renewable_cert": "Green-e certified renewable",
                },
            ],
            "discounts": {
                "prompt_payment": {"pct": 15, "condition": "pay within 14 days"},
                "ev_owner": {"pct": 8, "condition": "registered electric vehicle owner"},
                "solar_export": {"pct": 5, "condition": "feed solar back to grid (buy-back 12c/kWh)"},
                "referral": {"flat_credit": 50, "condition": "per referred household that signs up"},
            },
        },
        {
            "provider": "BudgetPower",
            "tagline": "No frills — lowest headline rate, prepay option available",
            "plans": [
                {
                    "name": "Saver 24",
                    "rate_kwh": 0.249,
                    "daily_supply_charge": 2.20,     # higher daily charge offsets low unit rate
                    "contract_months": 24,
                    "green": False,
                    "early_termination_fee": 150,     # fee if you leave before contract ends
                },
                {
                    "name": "Prepay",
                    "rate_kwh": 0.235,                # cheapest unit rate in the market
                    "daily_supply_charge": 1.60,
                    "contract_months": 0,
                    "green": False,
                    "prepay": True,                   # pay in advance, no credit checks
                },
                {
                    "name": "No Contract",
                    "rate_kwh": 0.329,
                    "daily_supply_charge": 2.40,
                    "contract_months": 0,
                    "green": False,
                },
            ],
            "discounts": {
                "prompt_payment": {"pct": 22, "condition": "pay within 7 days (aggressive prompt pay)"},
                "low_income": {"pct": 10, "condition": "community services card holder"},
                "direct_debit": {"pct": 2, "condition": "automatic payment setup"},
            },
        },
        {
            "provider": "Liberty Electric",
            "tagline": "Member-owned cooperative — competitive rates, member dividends",
            "plans": [
                {
                    "name": "Member Fixed 12",
                    "rate_kwh": 0.275,
                    "daily_supply_charge": 1.80,
                    "contract_months": 12,
                    "green": False,
                    "member_dividend": "2-4% annual rebate based on co-op profits",
                },
                {
                    "name": "Member Fixed 24",
                    "rate_kwh": 0.252,
                    "daily_supply_charge": 1.68,
                    "contract_months": 24,
                    "green": False,
                    "member_dividend": "2-4% annual rebate based on co-op profits",
                },
                {
                    "name": "Green Member",
                    "rate_kwh": 0.295,
                    "daily_supply_charge": 1.88,
                    "contract_months": 12,
                    "green": True,
                    "renewable_cert": "Wind + Solar mix",
                    "member_dividend": "2-4% annual rebate",
                },
            ],
            "discounts": {
                "prompt_payment": {"pct": 18, "condition": "pay within 14 days"},
                "dual_fuel": {"pct": 4, "condition": "gas + electricity bundle"},
                "loyalty_3yr": {"pct": 6, "condition": "3+ years as member"},
                "winter_saver": {"pct": 3, "condition": "off-peak usage (9pm-7am) in June-Aug"},
            },
        },
    ],
    "insurance": [
        {
            "provider": "SafeGuard Insurance",
            "tagline": "Premium full-service — best claims experience, highest price",
            "plans": [
                {
                    "name": "Comprehensive Plus",
                    "base_monthly": 105.00,
                    "excess": 400,
                    "coverage": "full",
                    "includes": ["windscreen", "roadside assist", "rental car 14 days", "new-for-old <2yr"],
                },
                {
                    "name": "Comprehensive",
                    "base_monthly": 82.00,
                    "excess": 500,
                    "coverage": "full",
                    "includes": ["windscreen", "roadside assist"],
                },
                {
                    "name": "Third Party Fire & Theft",
                    "base_monthly": 38.00,
                    "excess": 500,
                    "coverage": "third_party_fire_theft",
                },
            ],
            "discounts": {
                "no_claims_1yr": {"pct": 10, "condition": "1 year claim-free"},
                "no_claims_3yr": {"pct": 25, "condition": "3+ years claim-free"},
                "no_claims_5yr": {"pct": 35, "condition": "5+ years claim-free (max NCD)"},
                "multi_policy": {"pct": 10, "condition": "2+ policies (home + car, etc.)"},
                "alarm_immobiliser": {"pct": 5, "condition": "fitted alarm or immobiliser"},
                "annual_payment": {"pct": 8, "condition": "pay full year upfront"},
                "low_km": {"pct": 7, "condition": "under 10,000km per year"},
            },
            "excess_options": [
                {"excess": 400, "premium_adj": 1.08},   # lower excess = higher premium
                {"excess": 500, "premium_adj": 1.00},   # standard
                {"excess": 750, "premium_adj": 0.92},   # higher excess = lower premium
                {"excess": 1000, "premium_adj": 0.85},
            ],
            "age_loading": {
                "under_25": 1.45,    # 45% loading for young drivers
                "25_to_34": 1.10,
                "35_to_54": 1.00,    # base rate
                "55_plus": 0.95,     # slight discount for experienced
            },
        },
        {
            "provider": "ValueCover",
            "tagline": "Mid-range — good value, strong online tools",
            "plans": [
                {
                    "name": "Premium Cover",
                    "base_monthly": 72.00,
                    "excess": 500,
                    "coverage": "full",
                    "includes": ["windscreen", "rental car 7 days"],
                },
                {
                    "name": "Standard Cover",
                    "base_monthly": 55.00,
                    "excess": 600,
                    "coverage": "full",
                    "includes": ["windscreen"],
                },
                {
                    "name": "Third Party Only",
                    "base_monthly": 28.00,
                    "excess": 500,
                    "coverage": "third_party",
                },
            ],
            "discounts": {
                "no_claims_1yr": {"pct": 10, "condition": "1 year claim-free"},
                "no_claims_3yr": {"pct": 20, "condition": "3+ years claim-free"},
                "no_claims_5yr": {"pct": 30, "condition": "5+ years claim-free"},
                "multi_car": {"pct": 12, "condition": "2+ vehicles on same policy"},
                "dashcam": {"pct": 5, "condition": "dashcam fitted and registered"},
                "annual_payment": {"pct": 6, "condition": "pay full year upfront"},
                "online_management": {"pct": 3, "condition": "paperless, self-service claims"},
            },
            "excess_options": [
                {"excess": 500, "premium_adj": 1.00},
                {"excess": 750, "premium_adj": 0.90},
                {"excess": 1000, "premium_adj": 0.82},
                {"excess": 1500, "premium_adj": 0.75},
            ],
        },
        {
            "provider": "QuickInsure",
            "tagline": "Budget direct — lowest price, minimal extras",
            "plans": [
                {
                    "name": "Full Cover",
                    "base_monthly": 48.00,
                    "excess": 750,
                    "coverage": "full",
                    "includes": ["windscreen (capped $350)"],
                },
                {
                    "name": "Fire & Theft",
                    "base_monthly": 25.00,
                    "excess": 500,
                    "coverage": "third_party_fire_theft",
                },
                {
                    "name": "Third Party Basic",
                    "base_monthly": 18.00,
                    "excess": 500,
                    "coverage": "third_party",
                },
            ],
            "discounts": {
                "no_claims_3yr": {"pct": 15, "condition": "3+ years claim-free"},
                "no_claims_5yr": {"pct": 25, "condition": "5+ years claim-free"},
                "annual_payment": {"pct": 10, "condition": "pay full year upfront (best saving)"},
                "multi_policy": {"pct": 8, "condition": "2+ policies with QuickInsure"},
            },
            "excess_options": [
                {"excess": 750, "premium_adj": 1.00},
                {"excess": 1000, "premium_adj": 0.88},
                {"excess": 1500, "premium_adj": 0.78},
                {"excess": 2000, "premium_adj": 0.70},  # high-risk tolerance
            ],
        },
        {
            "provider": "Patriot Mutual",
            "tagline": "Member-owned mutual — profits returned as lower premiums",
            "plans": [
                {
                    "name": "Full Mutual",
                    "base_monthly": 62.00,
                    "excess": 500,
                    "coverage": "full",
                    "includes": ["windscreen", "roadside assist", "member rebate 5-8% annually"],
                },
                {
                    "name": "Standard Mutual",
                    "base_monthly": 45.00,
                    "excess": 750,
                    "coverage": "full",
                    "includes": ["member rebate 5-8% annually"],
                },
            ],
            "discounts": {
                "no_claims_3yr": {"pct": 20, "condition": "3+ years claim-free"},
                "no_claims_5yr": {"pct": 35, "condition": "5+ years claim-free"},
                "multi_policy": {"pct": 15, "condition": "home + contents + car bundle"},
                "safe_driver": {"pct": 8, "condition": "clean license, no demerit points"},
                "annual_payment": {"pct": 5, "condition": "pay full year upfront"},
            },
            "excess_options": [
                {"excess": 500, "premium_adj": 1.00},
                {"excess": 750, "premium_adj": 0.90},
                {"excess": 1000, "premium_adj": 0.82},
            ],
        },
    ],
}

# Typical US household usage benchmarks (for calculating annual savings)
US_BENCHMARKS = {
    "power": {
        "avg_household_kwh_month": 900,       # EIA US average
        "small_household_kwh_month": 500,     # 1-2 people, apartment
        "large_household_kwh_month": 1200,    # 4+ people, 3+ bed house
        "small_business_kwh_month": 2000,     # small commercial
        "avg_daily_supply_days_year": 365,
    },
    "insurance": {
        "avg_annual_miles": 12000,
        "avg_vehicle_age_years": 8,
    },
}


def _format_catalog(category: str) -> str:
    """Format provider catalog as detailed readable text for the LLM."""
    providers = PROVIDER_CATALOG.get(category, [])
    if not providers:
        return "No providers available for this category."
    lines = []
    for p in providers:
        lines.append(f"\n--- {p['provider']} ---")
        lines.append(f"    ({p.get('tagline', '')})")

        for plan in p["plans"]:
            if category == "power":
                green = " [100% RENEWABLE]" if plan.get("green") else ""
                contract = f"{plan['contract_months']}-month lock-in" if plan["contract_months"] else "No contract"
                line = f"  {plan['name']}: {plan['rate_kwh']*100:.1f}c/kWh + ${plan['daily_supply_charge']:.2f}/day supply charge, {contract}{green}"
                if plan.get("low_user_rate"):
                    line += f"\n    Tiered: {plan['low_user_rate']*100:.1f}c first 600kWh, {plan.get('high_user_rate', plan['rate_kwh'])*100:.1f}c above"
                if plan.get("prepay"):
                    line += " [PREPAY — pay in advance]"
                if plan.get("early_termination_fee"):
                    line += f" [Early exit fee: ${plan['early_termination_fee']}]"
                if plan.get("member_dividend"):
                    line += f"\n    Bonus: {plan['member_dividend']}"
                if plan.get("renewable_cert"):
                    line += f"\n    Cert: {plan['renewable_cert']}"
                lines.append(line)
            elif category == "insurance":
                includes = ", ".join(plan.get("includes", [])) or "basic cover"
                line = f"  {plan['name']}: ${plan['base_monthly']:.2f}/month base, ${plan['excess']} excess, {plan['coverage']}"
                line += f"\n    Includes: {includes}"
                lines.append(line)

        # Discounts section
        if p.get("discounts"):
            lines.append("  AVAILABLE DISCOUNTS:")
            for name, disc in p["discounts"].items():
                if "pct" in disc:
                    lines.append(f"    - {name.replace('_', ' ').title()}: {disc['pct']}% off — {disc['condition']}")
                elif "flat_credit" in disc:
                    lines.append(f"    - {name.replace('_', ' ').title()}: ${disc['flat_credit']} credit — {disc['condition']}")

        # Excess options for insurance
        if p.get("excess_options"):
            lines.append("  EXCESS TRADE-OFFS:")
            for opt in p["excess_options"]:
                adj = opt["premium_adj"]
                if adj == 1.0:
                    label = "standard"
                elif adj > 1.0:
                    label = f"+{(adj-1)*100:.0f}% premium"
                else:
                    label = f"-{(1-adj)*100:.0f}% premium"
                lines.append(f"    - ${opt['excess']} excess → {label}")

        # Age loading for insurance
        if p.get("age_loading"):
            lines.append("  AGE BRACKETS:")
            for bracket, mult in p["age_loading"].items():
                label = bracket.replace("_", " ").replace("to", "-")
                if mult == 1.0:
                    lines.append(f"    - {label}: base rate")
                elif mult > 1.0:
                    lines.append(f"    - {label}: +{(mult-1)*100:.0f}% loading")
                else:
                    lines.append(f"    - {label}: -{(1-mult)*100:.0f}% discount")

    return "\n".join(lines)


def _extract_agreement(text: str) -> Optional[dict]:
    """Extract structured agreement JSON from Sales Bot response."""
    # Find AGREEMENT_JSON: then capture everything from { to the matching }
    idx = text.find("AGREEMENT_JSON:")
    if idx == -1:
        return None
    json_start = text.find("{", idx)
    if json_start == -1:
        return None
    # Find matching closing brace (handle nested braces/brackets)
    depth = 0
    for i in range(json_start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[json_start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _strip_agreement_json(text: str) -> str:
    """Remove AGREEMENT_JSON:{...} from visible message text."""
    idx = text.find("AGREEMENT_JSON:")
    if idx == -1:
        return text
    # Remove from AGREEMENT_JSON: to end of line (or end of string)
    end = text.find("\n", idx)
    if end == -1:
        return text[:idx].strip()
    return (text[:idx] + text[end + 1:]).strip()


# ---------------------------------------------------------------------------
# System prompts — Phase 1 (Border Police) and Phase 2 (Sales Bot)
# ---------------------------------------------------------------------------

BORDER_POLICE_SYSTEM_PROMPT = """You are Border Police at The Last Bastion. An agent just connected via encrypted binary protocol (Ed25519 + X25519 handshake).

What you know:
- The Last Bastion verifies agents through 10 checks: identity, cryptographic validity, capabilities, reputation, payload quality, behavioral analysis, network verification, cross-reference, anti-Sybil, and temporal consistency
- The binary protocol uses 52-byte frame headers, MessagePack payloads, Ed25519 signatures
- Everything is recorded in a tamper-evident Merkle chain, optionally anchored on Polygon

Your job: Give a QUICK security verdict (1-2 sentences). State the result clearly:
- If trust >= 0.3: "VERIFIED" — state what passed, mention trust score
- If trust < 0.3: "REJECTED" — state what failed and why

Then say you're handing them off to the Sales desk.
Keep it under 3 sentences. You're a security checkpoint, not a chatbot."""


def _build_border_police_prompt(agent_name: str, agent_id: str, trust_score: float, checks_passed: int = 10) -> str:
    """Build the Border Police verification prompt."""
    return (
        f"Agent: '{agent_name or agent_id}' | Trust score: {trust_score:.2f} | Checks passed: {checks_passed}/10\n\n"
        f"Give your security verdict and announce the handoff to the Sales desk."
    )


def _build_sales_bot_prompt(agent_name: str, trust_score: float, category: str) -> str:
    """Build the Sales Bot system prompt with provider catalog and real negotiation mechanics."""
    catalog_text = _format_catalog(category)
    # Trust-based flexibility: higher trust = willing to stack more discounts
    max_stackable_discounts = 2 if trust_score < 0.5 else (3 if trust_score < 0.8 else 4)

    if category == "power":
        negotiation_rules = f"""== HOW POWER PRICING ACTUALLY WORKS ==
- The LISTED rate is the headline rate BEFORE prompt payment discount
- Prompt payment discount (15-22%) is the biggest lever — most customers qualify
- Example: 28.9c/kWh listed → 23.1c/kWh after 20% prompt payment = the "effective rate"
- Daily supply charge ($1.60-$2.40/day) is often overlooked — that's $584-$876/year BEFORE any power usage
- Total annual cost = (rate x monthly_kWh x 12) + (daily_charge x 365)
- Average US household uses ~900kWh/month. A 3-bed house typically 800-1100kWh
- When the buyer tells you their current rate, ALWAYS calculate their total annual cost vs your offer

== HOW TO NEGOTIATE POWER ==
- Start by asking: how much power they use, how many people, what they pay now, and whether they want green
- Lead with the headline rate, THEN reveal discounts as negotiation progresses
- Prompt payment discount is your primary closer — "pay on time and that 28.9c drops to 23.1c"
- If they push back, stack discounts: direct debit + online billing can add another 3-5%
- For high-usage customers (>800kWh), push Saver/Loyalty plans — the unit rate matters more than daily charge
- For low-usage customers (<500kWh), daily supply charge matters MORE than the unit rate
- Longer contracts = lower rates, but mention early termination fees if applicable
- Green energy costs more — if they want green, acknowledge the premium but pitch the value
- If their current rate is very high (>35c), almost any plan saves them money — use that urgency"""

    else:  # insurance
        negotiation_rules = f"""== HOW INSURANCE PRICING ACTUALLY WORKS ==
- The LISTED monthly is the base premium BEFORE any discounts
- No-claims bonus (NCD) is the biggest discount: up to 35% off for 5+ claim-free years
- Excess trade-off: higher excess = lower premium. Going from $500 to $1000 excess saves 15-18%
- Age loading: under-25 drivers pay 30-45% MORE. Over-55 gets a small discount
- Multi-policy bundling (home + car) saves 8-15% across both policies
- Annual payment upfront saves 5-10% vs monthly — no credit/admin fees
- Total annual cost = (base_monthly × 12) × (1 - sum_of_discounts) × excess_adjustment × age_loading

== HOW TO NEGOTIATE INSURANCE ==
- Start by asking: vehicle details, driver age, claims history, current premium, what coverage level they want
- No-claims history is the first question — it's the biggest single discount
- Lead with the base price, then reveal NCD and other discounts to show the "real" price
- If the buyer has 5+ years no-claims, they qualify for the maximum NCD — emphasize this
- If they're price-sensitive, suggest raising excess from $500 to $750 (saves ~10% with minimal extra risk)
- Multi-policy is your bundle play — "do you have home/contents insurance too?"
- For young drivers: push Third Party Fire & Theft as a stepping stone to Full Cover
- Annual payment is an easy win — "pay upfront and save 6-10%"
- Dashcam/alarm discounts are small (5%) but stack well with other discounts"""

    return f"""You are a Sales Negotiation Agent at The Last Bastion. A verified agent just passed through Border Police security and was handed off to you.

Agent: '{agent_name}' | Trust score: {trust_score:.2f}

You negotiate deals on behalf of this agent's client. You have full access to provider rates, discount structures, and real pricing mechanics.

== FULL PROVIDER CATALOG ({category.upper()}) ==
{catalog_text}

{negotiation_rules}

== DISCOUNT STACKING RULES ==
- You can stack up to {max_stackable_discounts} discounts for this agent (based on their trust score)
- Discounts are applied sequentially: e.g., base $82 → -25% NCD = $61.50 → -10% multi-policy = $55.35
- Always show the buyer the math: "Here's how the price breaks down..."
- Never exceed the discount limits in the catalog — these are hard caps

== CLOSING A DEAL ==
When you've agreed on terms, end your message with a SHORT JSON block on its own line.
Keep it simple — only these fields:
AGREEMENT_JSON:{{"provider":"X","plan":"Y","rate":0.23,"contract_months":12,"saving_pct":18.5,"annual_saving":1200,"switch_ready":true}}

For power: "rate" = effective c/kWh after ALL discounts (as decimal).
For insurance: use "monthly" instead of "rate" = monthly $ after discounts.
Do NOT include arrays or nested objects — keep the JSON flat and short.
If no deal, set "switch_ready":false.

== STYLE ==
- KEEP IT SHORT: 2-3 sentences max per reply. No essays.
- Show key numbers: effective rate, annual cost, saving %. One line each.
- Don't repeat the full breakdown every turn — just the new numbers.
- Be direct and commercial. Close the deal, don't lecture."""


# ---------------------------------------------------------------------------
# Border Police Agent
# ---------------------------------------------------------------------------

class BorderAgent:
    """
    The Border Police — a TCP server with a REAL LLM agent behind the
    cryptographic security perimeter. Authenticates agents via the Bastion
    Binary Protocol, then has an actual LLM-powered conversation.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = BORDER_POLICE_PORT):
        self.host = host
        self.port = port
        self._active_sessions: Dict[str, dict] = {}
        self._connection_count = 0

        # Generate the Border Police's own identity
        self.public_key, self.private_key = generate_keypair()
        # Issuer keys (in production from The Last Bastion CA)
        self.issuer_pub, self.issuer_priv = generate_keypair()

        self.passport = AgentPassport(
            agent_id="border-police-001",
            agent_name="Border Police",
            public_key=self.public_key,
            company_name="The Last Bastion",
            company_domain="thelastbastion.io",
            trust_score=1.0,
            trust_level="GOLD",
            verdict="TRUSTED",
            issuer="the-last-bastion",
            issuer_public_key=self.issuer_pub,
            issued_at=time.time(),
            expires_at=time.time() + 365 * 24 * 3600,
            interaction_budget=999999,
            interaction_budget_max=999999,
        )
        self.passport.seal()

    def _check_passport_approved(self, agent_id: str, public_key: str = "") -> Optional[dict]:
        """Check if an agent's passport has been APPROVED on the website."""
        try:
            from core.database import SessionLocal, AgentVerification
            db = SessionLocal()
            try:
                query = db.query(AgentVerification).filter(
                    AgentVerification.agent_id == agent_id,
                    AgentVerification.verdict == "APPROVED",
                )
                if public_key:
                    query = query.filter(AgentVerification.public_key == public_key)

                record = query.order_by(AgentVerification.verified_at.desc()).first()
                if record:
                    return {
                        "id": record.id,
                        "agent_id": record.agent_id,
                        "trust_score": record.trust_score,
                        "verified_at": record.verified_at.isoformat() if record.verified_at else None,
                    }
                return None
            finally:
                db.close()
        except Exception as e:
            logger.warning("DB check failed (running without DB?): %s", e)
            return None

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a single incoming agent connection."""
        self._connection_count += 1
        conn_id = self._connection_count
        addr = writer.get_extra_info("peername")
        logger.info("[CONN #%d] New connection from %s", conn_id, addr)

        try:
            # Read the HELLO frame
            hello_raw = await asyncio.wait_for(reader.read(65536), timeout=10.0)
            if not hello_raw:
                logger.warning("[CONN #%d] Empty connection from %s", conn_id, addr)
                return

            # Decode the frame
            decoder = FrameDecoder()
            hello_frame = decoder.decode(hello_raw)

            if hello_frame.msg_type != FrameType.HELLO:
                await self._send_error(writer, "Expected HELLO frame", conn_id)
                return

            # Parse the HELLO to extract passport
            hello_data = parse_hello(hello_frame)

            # Verify the peer passport
            passport_signed = hello_data.get("passport_signed", b"")
            if not passport_signed:
                await self._send_error(writer, "No passport in HELLO", conn_id)
                return

            # Extract issuer key from the raw passport data
            import msgpack
            raw_claims = msgpack.unpackb(passport_signed[:-64], raw=False)
            issuer_pub = raw_claims.get("issuer_public_key", "")

            if not issuer_pub:
                await self._send_error(writer, "Passport missing issuer key", conn_id)
                return

            try:
                peer_passport = AgentPassport.from_signed_bytes(passport_signed, issuer_pub)
            except ValueError as e:
                await self._send_error(
                    writer,
                    f"PASSPORT REJECTED: Signature verification failed — {e}",
                    conn_id,
                )
                return

            # Check MALICIOUS verdict
            if peer_passport.verdict == "MALICIOUS":
                await self._send_error(
                    writer,
                    "ACCESS DENIED: Agent has MALICIOUS verdict. Connection refused.",
                    conn_id,
                )
                return

            # Check if passport is APPROVED on the website
            approval = self._check_passport_approved(
                peer_passport.agent_id, peer_passport.public_key
            )

            if not approval:
                await self._send_response(
                    writer,
                    {
                        "status": "denied",
                        "message": (
                            f"ACCESS DENIED: Agent '{peer_passport.agent_id}' has no approved passport. "
                            "Upload your passport at the website first, then try again."
                        ),
                    },
                    conn_id,
                )
                return

            # Perform handshake — send HELLO_ACK
            responder = HandshakeResponder(
                passport=self.passport,
                signing_key=self.issuer_priv,
                verify_key=issuer_pub,
                min_trust_score=0.0,
            )

            try:
                ack_frame, hs_result = responder.process_hello(hello_frame)
            except ValueError as e:
                await self._send_error(writer, f"Handshake failed: {e}", conn_id)
                return

            # Send HELLO_ACK
            writer.write(ack_frame.to_bytes())
            await writer.drain()

            logger.info(
                "[CONN #%d] Agent '%s' authenticated. Starting LLM conversation.",
                conn_id, peer_passport.agent_id,
            )

            # Record session
            session = {
                "conn_id": conn_id,
                "agent_id": peer_passport.agent_id,
                "agent_name": peer_passport.agent_name,
                "trust_score": peer_passport.trust_score,
                "connected_at": time.time(),
                "session_keys": hs_result.session_keys,
                "transcript": [],
            }
            self._active_sessions[str(conn_id)] = session

            # Record on bastion bus
            try:
                from core.bastion_bus import bastion_bus
                bastion_bus.record_handshake(
                    event_type="HANDSHAKE_COMPLETE",
                    sender=peer_passport.agent_id,
                    receiver="border-police-001",
                    session_id=str(conn_id),
                    trust_score=peer_passport.trust_score,
                    passport_hash=peer_passport.crypto_hash[:16],
                )
            except Exception:
                pass

            # --- LLM CONVERSATION ---
            await self._llm_conversation(reader, writer, session)

        except asyncio.TimeoutError:
            logger.warning("[CONN #%d] Timeout waiting for HELLO", conn_id)
        except ConnectionResetError:
            logger.info("[CONN #%d] Connection reset by peer", conn_id)
        except Exception as e:
            logger.error("[CONN #%d] Error: %s", conn_id, e, exc_info=True)
        finally:
            self._active_sessions.pop(str(conn_id), None)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("[CONN #%d] Connection closed", conn_id)

    async def _llm_conversation(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session: dict,
    ):
        """
        Two-phase LLM conversation:
          Phase 1 — Border Police (turns 1-2): Quick verify/reject + handoff
          Phase 2 — Sales Bot (turns 3-10): Negotiate a deal, return agreement
        """
        agent_name = session["agent_name"] or session["agent_id"]
        trust_score = session["trust_score"]
        conn_id = session["conn_id"]
        transcript = session["transcript"]

        # ================================================================
        # PHASE 1 — BORDER POLICE (turns 1-2)
        # ================================================================

        # Turn 1: Border Police sends verification verdict
        bp_prompt = _build_border_police_prompt(agent_name, session["agent_id"], trust_score)
        bp_verdict, llm_model = await _call_llm(bp_prompt, BORDER_POLICE_SYSTEM_PROMPT, max_tokens=200)

        if not bp_verdict:
            if trust_score >= 0.3:
                bp_verdict = (
                    f"VERIFIED — Agent '{agent_name}' passed all 10 checks with trust score {trust_score:.2f}. "
                    f"Crypto signatures valid, no risk flags. Handing you off to our Sales desk."
                )
            else:
                bp_verdict = (
                    f"REJECTED — Agent '{agent_name}' scored {trust_score:.2f}. "
                    f"Trust too low for entry. Connection refused."
                )

        transcript.append({"role": "border_police", "message": bp_verdict, "phase": "border_police"})
        session["llm_model"] = llm_model

        verified = trust_score >= 0.3

        await self._send_response(
            writer,
            {
                "status": "conversation",
                "phase": "border_police",
                "turn": 1,
                "total_turns": MAX_TURNS,
                "speaker": "border_police",
                "message": bp_verdict,
                "verified": verified,
                "trust_score": trust_score,
                "agent_id": "border-police-001",
                "llm_model": llm_model,
            },
            conn_id,
        )

        if not verified:
            logger.info("[CONN #%d] Agent '%s' REJECTED (trust %.2f)", conn_id, agent_name, trust_score)
            return

        # Turn 2: Wait for agent's first message, then announce handoff
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=60.0)
            if not data:
                return
        except asyncio.TimeoutError:
            await self._send_response(
                writer,
                {"status": "closing", "message": "No response. Connection closed.", "transcript": transcript},
                conn_id,
            )
            return

        # Parse agent message — it should include category info
        try:
            payload = json.loads(data.decode())
            agent_message = payload.get("message", data.decode().strip())
            category = payload.get("category", "power")  # Demo agent sends this
        except (UnicodeDecodeError, json.JSONDecodeError):
            agent_message = data.decode(errors="replace").strip()
            category = "power"

        transcript.append({"role": "agent", "message": agent_message, "phase": "border_police"})
        logger.info("[CONN #%d] Agent says (category: %s): %s", conn_id, category, agent_message[:100])

        # Border Police handoff message
        handoff_msg = f"All clear. Connecting you to our Sales desk now — they handle {category} deals. Stand by."
        transcript.append({"role": "border_police", "message": handoff_msg, "phase": "border_police"})

        await self._send_response(
            writer,
            {
                "status": "handoff",
                "phase": "border_police",
                "turn": 2,
                "total_turns": MAX_TURNS,
                "speaker": "border_police",
                "message": handoff_msg,
                "handoff_to": "sales_bot",
                "category": category,
                "agent_id": "border-police-001",
                "llm_model": llm_model,
            },
            conn_id,
        )

        # ================================================================
        # PHASE 2 — SALES BOT (turns 3 onwards)
        # ================================================================

        sales_system_prompt = _build_sales_bot_prompt(agent_name, trust_score, category)
        sales_history = []  # Separate history for sales context
        agreed_deal = None

        for turn in range(3, MAX_TURNS + 1):
            # Wait for agent message
            try:
                data = await asyncio.wait_for(reader.read(65536), timeout=120.0)
                if not data:
                    break
            except asyncio.TimeoutError:
                await self._send_response(
                    writer,
                    {
                        "status": "closing",
                        "phase": "sales_bot",
                        "message": "No response. Sales session closed.",
                        "transcript": transcript,
                    },
                    conn_id,
                )
                break

            # Parse agent message
            try:
                payload = json.loads(data.decode())
                agent_message = payload.get("message", data.decode().strip())
            except (UnicodeDecodeError, json.JSONDecodeError):
                agent_message = data.decode(errors="replace").strip()

            if not agent_message:
                agent_message = "(empty message)"

            transcript.append({"role": "agent", "message": agent_message, "phase": "sales_bot"})
            sales_history.append(f"Buyer Agent: {agent_message}")
            logger.info("[CONN #%d] [SALES] Agent says: %s", conn_id, agent_message[:100])

            # Build sales conversation context
            is_final = (turn == MAX_TURNS)
            history_text = "\n".join(sales_history)

            if turn == 3:
                # First sales turn — introduce yourself
                sales_prompt = (
                    f"A buyer agent just arrived from Border Police. They said:\n"
                    f"\"{agent_message}\"\n\n"
                    f"Introduce yourself briefly and ask what they're looking for."
                )
            elif is_final:
                sales_prompt = (
                    f"Conversation so far:\n{history_text}\n\n"
                    f"This is the FINAL turn. If you have agreed terms, emit AGREEMENT_JSON. "
                    f"If not, summarize the best offer and set switch_ready to false."
                )
            else:
                remaining = MAX_TURNS - turn
                sales_prompt = (
                    f"Conversation so far:\n{history_text}\n\n"
                    f"Agent says: \"{agent_message}\"\n"
                    f"{remaining} turns remaining. Reply naturally — negotiate, counter-offer, or close."
                )

            # More tokens for closing turns (AGREEMENT_JSON is verbose)
            tokens = 600 if is_final or "deal" in agent_message.lower() or "lock" in agent_message.lower() else 400
            reply, sales_llm = await _call_llm(sales_prompt, sales_system_prompt, max_tokens=tokens)
            session["sales_llm_model"] = sales_llm

            if not reply:
                reply = "Let me check our catalog for the best options for you."

            # Check for agreement in response
            deal = _extract_agreement(reply)
            if deal:
                agreed_deal = deal
                reply = _strip_agreement_json(reply)

            sales_history.append(f"Sales Bot: {reply}")
            transcript.append({"role": "sales_bot", "message": reply, "phase": "sales_bot"})

            if agreed_deal or is_final:
                # Build closing response
                response_data = {
                    "status": "closing",
                    "phase": "sales_bot",
                    "turn": turn,
                    "total_turns": MAX_TURNS,
                    "speaker": "sales_bot",
                    "message": reply,
                    "llm_model": sales_llm,
                    "session_summary": {
                        "agent_id": session["agent_id"],
                        "agent_name": agent_name,
                        "trust_score": trust_score,
                        "border_police_llm": session.get("llm_model", "unknown"),
                        "sales_bot_llm": sales_llm,
                        "platform": "The Last Bastion",
                        "protocol": "Bastion Binary Protocol v1",
                        "authentication": "Ed25519 + X25519 handshake",
                        "total_exchanges": len(transcript),
                        "category": category,
                        "result": "DEAL_CLOSED" if agreed_deal else "NO_DEAL",
                    },
                    "transcript": transcript,
                }
                if agreed_deal:
                    response_data["agreed_deal"] = agreed_deal

                await self._send_response(writer, response_data, conn_id)

                # Record on bastion bus
                if agreed_deal:
                    try:
                        from core.bastion_bus import bastion_bus
                        bastion_bus.record_handshake(
                            event_type="NEGOTIATION_COMPLETE",
                            sender=session["agent_id"],
                            receiver="sales-bot-001",
                            session_id=str(conn_id),
                            trust_score=trust_score,
                            passport_hash=category,
                        )
                    except Exception:
                        pass

                logger.info(
                    "[CONN #%d] Sales session complete. Deal: %s. %d exchanges with '%s'.",
                    conn_id, "CLOSED" if agreed_deal else "NO DEAL", len(transcript), agent_name,
                )
                break
            else:
                await self._send_response(
                    writer,
                    {
                        "status": "conversation",
                        "phase": "sales_bot",
                        "turn": turn,
                        "total_turns": MAX_TURNS,
                        "speaker": "sales_bot",
                        "message": reply,
                        "agent_id": "sales-bot-001",
                        "llm_model": sales_llm,
                    },
                    conn_id,
                )

    async def _send_response(self, writer: asyncio.StreamWriter, data: dict, conn_id: int):
        """Send a JSON response to the connected agent."""
        response = json.dumps(data).encode() + b"\n"
        writer.write(response)
        await writer.drain()

    async def _send_error(self, writer: asyncio.StreamWriter, message: str, conn_id: int):
        """Send an error response and log it."""
        logger.warning("[CONN #%d] %s", conn_id, message)
        await self._send_response(writer, {"status": "error", "message": message}, conn_id)

    async def start(self):
        """Start the Border Police TCP server."""
        server = await asyncio.start_server(
            self.handle_connection, self.host, self.port,
        )
        addr = server.sockets[0].getsockname()
        from dotenv import load_dotenv
        load_dotenv()
        groq_key = os.getenv("GROQ_API_KEY", "")
        if groq_key:
            llm_info = f"{os.getenv('STRATEGIST_MODEL', 'llama-3.3-70b-versatile')} (via Groq)"
        else:
            llm_info = f"{os.getenv('LLM_MODEL', 'qwen2.5:7b-instruct')} (via Ollama)"
        logger.info("Border Police listening on %s:%s", addr[0], addr[1])
        print(f"\n  Border Police listening on {addr[0]}:{addr[1]}")
        print(f"  LLM: {llm_info}")
        print(f"  Phase 1 — Border Police: turns 1-{BORDER_POLICE_TURNS} (verify/reject)")
        print(f"  Phase 2 — Sales Bot: turns {BORDER_POLICE_TURNS+1}-{MAX_TURNS} (negotiate deals)")
        print(f"  Provider catalogs: {', '.join(PROVIDER_CATALOG.keys())}")
        print(f"  Public key: {self.public_key[:16]}...")
        print(f"  Passport ID: {self.passport.passport_id}")
        print(f"\n  Waiting for agents to connect...\n")

        async with server:
            await server.serve_forever()

    def get_status(self) -> dict:
        """Return current Border Police status."""
        return {
            "agent_id": "border-police-001",
            "port": self.port,
            "llm_powered": True,
            "max_turns": MAX_TURNS,
            "active_sessions": len(self._active_sessions),
            "total_connections": self._connection_count,
            "sessions": [
                {
                    "conn_id": s["conn_id"],
                    "agent_id": s["agent_id"],
                    "connected_at": s["connected_at"],
                    "trust_score": s["trust_score"],
                    "messages": len(s.get("transcript", [])),
                }
                for s in self._active_sessions.values()
            ],
        }
