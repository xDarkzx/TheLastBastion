"""
Demo Agent Web Server — FastAPI + inline HTML chat interface.

No npm, no React, no build step. A single Python file that serves
a complete chat UI. The LLM has tool-calling — just say "verify me"
or "run the demo" and it handles everything.

Endpoints:
  GET  /         → Chat web interface (inline HTML)
  POST /chat     → Talk to the demo agent (LLM decides what tools to call)
  POST /connect  → Run the full demo flow directly (no LLM needed)
  GET  /status   → Agent connection status
  GET  /proof    → Last demo run's transcript + evidence
  POST /reset    → Reset conversation and state
"""

import asyncio
import json
import logging
import os

# Load .env from project root (for GROQ_API_KEY etc.)
from pathlib import Path
_env_file = Path(__file__).resolve().parent.parent / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

try:
    from demo_agent.agent import DemoAgent
except ImportError:
    from agent import DemoAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("DemoWeb")

app = FastAPI(title="Demo Agent — The Last Bastion", version="2.0.0")
agent = DemoAgent()

_progress: list = []
_demo_running = False


class ChatRequest(BaseModel):
    message: str


@app.post("/chat")
async def chat(request: ChatRequest):
    """Chat with the demo agent. LLM decides whether to call tools."""
    result = await agent.chat(request.message)
    return result


@app.post("/connect")
async def connect():
    """Run the full demo flow directly."""
    global _progress, _demo_running

    if _demo_running:
        return JSONResponse(status_code=409, content={"error": "Demo already running."})

    _progress = []
    _demo_running = True

    async def on_progress(step_or_name, detail=""):
        if isinstance(step_or_name, dict):
            _progress.append(step_or_name)
        else:
            _progress.append({"step": step_or_name, "detail": detail})

    try:
        return await agent.run_full_demo(progress_callback=on_progress)
    finally:
        _demo_running = False


@app.get("/status")
async def status():
    return {**agent.get_status(), "demo_running": _demo_running, "progress": _progress}


@app.get("/proof")
async def proof():
    if not agent.last_proof:
        return {"message": "No demo run yet."}
    return agent.last_proof


@app.get("/progress")
async def progress():
    return {"steps": _progress, "running": _demo_running}


@app.post("/reset")
async def reset():
    agent.reset()
    return {"message": "Conversation and state reset."}


# ---------------------------------------------------------------------------
# Inline HTML Chat Interface
# ---------------------------------------------------------------------------

CHAT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Agent-to-Agent Trading Demo — The Last Bastion</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&family=Inter:wght@400;500;600&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Outfit', 'Inter', system-ui, -apple-system, sans-serif;
    background: #ffffff;
    color: #334155;
    min-height: 100vh;
  }
  .layout { display: flex; height: 100vh; overflow: hidden; }

  /* Left panel — info */
  .info-panel {
    width: 380px; min-width: 380px; background: #f8fafc;
    border-right: 1px solid #e2e8f0; overflow-y: auto;
    padding: 20px; display: flex; flex-direction: column; gap: 16px;
    height: 100vh;
  }
  .info-panel h1 { font-size: 16px; color: #0f172a; font-weight: 700; }
  .info-panel h2 {
    font-size: 12px; color: #94a3b8; text-transform: uppercase;
    letter-spacing: 1px; margin-top: 8px;
  }
  .info-panel p { font-size: 12px; color: #64748b; line-height: 1.6; }
  .info-panel .highlight { color: #334155; font-weight: 600; }
  .info-panel .dim { color: #94a3b8; }

  .flow-step {
    display: flex; gap: 10px; padding: 6px 0;
    font-size: 11px; color: #64748b;
  }
  .flow-num {
    width: 20px; height: 20px; border-radius: 50%;
    background: #e2e8f0; color: #475569; display: flex;
    align-items: center; justify-content: center;
    font-size: 10px; font-weight: 700; flex-shrink: 0;
  }
  .flow-num.active { background: #dcfce7; color: #16a34a; }
  .flow-arrow { color: #cbd5e1; text-align: center; padding: 2px 0; font-size: 10px; }

  .proto-box {
    background: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 8px;
    padding: 10px; font-family: 'Cascadia Code', 'Fira Code', monospace;
    font-size: 10px; color: #64748b; line-height: 1.5;
    white-space: pre; overflow-x: auto;
  }

  .agent-box {
    padding: 8px 10px; border-radius: 6px; margin: 4px 0;
    font-size: 11px;
  }
  .agent-box.bp { background: #eff6ff; border-left: 2px solid #3b82f6; color: #475569; }
  .agent-box.sales { background: #faf5ff; border-left: 2px solid #a855f7; color: #475569; }
  .agent-box.buyer { background: #f0fdf4; border-left: 2px solid #22c55e; color: #475569; }
  .agent-box .agent-label {
    font-size: 9px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.5px; margin-bottom: 2px;
  }
  .agent-box.bp .agent-label { color: #3b82f6; }
  .agent-box.sales .agent-label { color: #a855f7; }
  .agent-box.buyer .agent-label { color: #22c55e; }

  .status-badge {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600;
  }
  .status-badge.live { background: #dcfce7; color: #16a34a; }
  .status-badge.off { background: #fef2f2; color: #ef4444; }

  /* Right panel — chat */
  .chat-panel { flex: 1; display: flex; flex-direction: column; overflow: hidden; height: 100vh; }
  .chat-header {
    padding: 12px 20px; background: #f8fafc;
    border-bottom: 1px solid #e2e8f0;
    display: flex; align-items: center; justify-content: space-between;
  }
  .chat-header h2 { font-size: 14px; color: #0f172a; font-weight: 600; }
  .chat-area { flex: 1; overflow-y: auto; padding: 12px 20px; background: #ffffff; }
  .chat-messages { display: flex; flex-direction: column; gap: 8px; max-width: 700px; }
  .msg {
    max-width: 95%; padding: 8px 12px; border-radius: 8px;
    font-size: 13px; line-height: 1.5; word-wrap: break-word;
    white-space: pre-wrap;
  }
  .msg.agent {
    background: #f8fafc; border: 1px solid #e2e8f0;
    align-self: flex-start;
  }
  .msg.user {
    background: #0f172a; border: 1px solid #1e293b; color: #f8fafc;
    align-self: flex-end;
  }
  .msg.system {
    background: #f1f5f9; border: 1px solid #e2e8f0;
    align-self: center; text-align: center;
    font-size: 11px; color: #94a3b8; max-width: 100%;
  }
  .msg.tool-call {
    background: #faf5ff; border: 1px solid #e9d5ff;
    align-self: flex-start; font-size: 11px;
    font-family: 'Cascadia Code', 'Fira Code', monospace;
    border-left: 3px solid #a855f7; max-width: 100%;
  }
  .msg.tool-result {
    background: #f0fdf4; border: 1px solid #bbf7d0;
    align-self: flex-start; font-size: 11px;
    font-family: 'Cascadia Code', 'Fira Code', monospace;
    border-left: 3px solid #22c55e; max-width: 100%;
  }
  .msg .role {
    font-size: 10px; font-weight: 600; margin-bottom: 2px;
    text-transform: uppercase; letter-spacing: 0.3px;
  }
  .msg.agent .role { color: #3b82f6; }
  .msg.user .role { color: #94a3b8; }
  .msg.tool-call .role { color: #a855f7; }
  .msg.tool-result .role { color: #16a34a; }
  input[type="text"] {
    flex: 1; padding: 10px 14px;
    background: #ffffff; border: 1px solid #e2e8f0;
    border-radius: 8px; color: #0f172a; font-size: 13px; outline: none;
  }
  input[type="text"]:focus { border-color: #3b82f6; }
  button {
    padding: 8px 16px; border: none; border-radius: 8px;
    font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.2s;
  }
  .btn-send { background: #0f172a; color: white; }
  .btn-send:hover { background: #1e293b; }
  .btn-send:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-confirm {
    background: #16a34a; color: white; margin-top: 8px;
    padding: 6px 14px; font-size: 12px;
  }
  .btn-confirm:hover { background: #15803d; }
  .btn-confirm:disabled { opacity: 0.5; cursor: not-allowed; }
  .suggestions {
    display: flex; gap: 6px; padding: 6px 20px; flex-wrap: wrap;
  }
  .suggestion {
    padding: 5px 12px; background: #ffffff;
    border: 1px solid #e2e8f0; border-radius: 16px;
    font-size: 11px; color: #64748b; cursor: pointer;
    transition: all 0.2s;
  }
  .suggestion:hover { border-color: #3b82f6; color: #3b82f6; }
  .spinner {
    display: inline-block; width: 12px; height: 12px;
    border: 2px solid #94a3b8; border-top: 2px solid transparent;
    border-radius: 50%; animation: spin 0.8s linear infinite;
    margin-right: 4px; vertical-align: middle;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  @keyframes bounce { 0%,80%,100%{transform:translateY(0)} 40%{transform:translateY(-6px)} }
  .typing-indicator {
    display: flex; align-items: center; gap: 4px;
    padding: 10px 14px; max-width: 80px;
    background: #f1f5f9; border: 1px solid #e2e8f0;
    border-radius: 8px; align-self: flex-start;
  }
  .typing-dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: #94a3b8; animation: bounce 1.4s infinite ease-in-out;
  }
  .typing-dot:nth-child(2) { animation-delay: 0.2s; }
  .typing-dot:nth-child(3) { animation-delay: 0.4s; }
  .status-dot {
    width: 6px; height: 6px; border-radius: 50%;
    background: #22c55e; display: inline-block; margin-right: 4px;
    animation: pulse 2s infinite;
  }

  .verify-badge {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 3px 10px; border-radius: 16px; font-size: 11px;
    font-weight: 700; letter-spacing: 0.3px; margin-bottom: 6px;
  }
  .verify-badge.verified { background: #dcfce7; color: #16a34a; border: 1px solid #bbf7d0; }
  .verify-badge.rejected { background: #fef2f2; color: #ef4444; border: 1px solid #fecaca; }

  .phase-tag {
    display: inline-block; padding: 1px 6px; border-radius: 3px;
    font-size: 8px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.4px; margin-right: 4px;
  }
  .phase-tag.bp { background: #eff6ff; color: #3b82f6; }
  .phase-tag.sales { background: #faf5ff; color: #a855f7; }
  .phase-tag.buyer { background: #f0fdf4; color: #22c55e; }

  .transcript-box { margin-top: 8px; padding: 8px; background: #f8fafc; border-radius: 6px; border: 1px solid #e2e8f0; }
  .transcript-msg { padding: 4px 8px; margin: 3px 0; border-radius: 4px; font-size: 11px; }
  .transcript-msg.bp { background: #eff6ff; border-left: 2px solid #3b82f6; }
  .transcript-msg.sales { background: #faf5ff; border-left: 2px solid #a855f7; }
  .transcript-msg.da { background: #f0fdf4; border-left: 2px solid #22c55e; }
  .transcript-msg.handoff { background: #fffbeb; border-left: 2px solid #f59e0b; text-align: center; color: #b45309; font-weight: 600; font-size: 10px; }
  .transcript-label { font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; margin-bottom: 1px; }
  .transcript-msg.bp .transcript-label { color: #3b82f6; }
  .transcript-msg.sales .transcript-label { color: #a855f7; }
  .transcript-msg.da .transcript-label { color: #22c55e; }

  .deal-card {
    margin-top: 8px; padding: 12px; border-radius: 8px;
    background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
    border: 1px solid #bbf7d0;
  }
  .deal-card h3 { color: #16a34a; font-size: 13px; margin-bottom: 8px; }
  .deal-row { display: flex; justify-content: space-between; padding: 3px 0; font-size: 12px; }
  .deal-label { color: #64748b; }
  .deal-value { color: #0f172a; font-weight: 600; }
  .deal-saving { color: #16a34a; font-size: 16px; font-weight: 700; margin-top: 6px; }

  @media (max-width: 800px) {
    .layout { flex-direction: column; }
    .info-panel { width: 100%; min-width: auto; max-height: 40vh; }
  }
</style>
</head>
<body>
<div class="layout">

<!-- LEFT: Protocol & Architecture Info -->
<div class="info-panel">
  <div>
    <h1>Agent-to-Agent Trading Demo</h1>
    <p>A working demo of how AI agents could negotiate real-world deals (power prices, insurance rates) through an authenticated, encrypted channel.</p>
  </div>

  <div>
    <h2>What You're Seeing</h2>
    <p>Two independent LLM agents talking to each other over a <span class="highlight">custom binary protocol</span>. One represents you (the buyer). The other is a sales bot behind a security perimeter. They negotiate a deal and return the result.</p>
  </div>

  <div>
    <h2>Communication Flow</h2>
    <div class="flow-step"><div class="flow-num" id="f1">1</div><div>Buyer agent generates an <span class="highlight">Ed25519 cryptographic passport</span> (keypair + signed envelope)</div></div>
    <div class="flow-arrow">|</div>
    <div class="flow-step"><div class="flow-num" id="f2">2</div><div>Passport uploaded for <span class="highlight">10-check verification</span> (identity, crypto, behavioral, anti-Sybil, payload)</div></div>
    <div class="flow-arrow">|</div>
    <div class="flow-step"><div class="flow-num" id="f3">3</div><div>Passport approved — agent now has a <span class="highlight">trust score</span></div></div>
    <div class="flow-arrow">|</div>
    <div class="flow-step"><div class="flow-num" id="f4">4</div><div><span class="highlight">TCP connection</span> to Border Police (port 9200). Binary handshake: <span class="highlight">X25519 key exchange</span> for forward secrecy</div></div>
    <div class="flow-arrow">|</div>
    <div class="flow-step"><div class="flow-num" id="f5">5</div><div><span class="highlight">Border Police</span> (LLM) verifies passport, gives verdict, hands off to Sales Bot</div></div>
    <div class="flow-arrow">|</div>
    <div class="flow-step"><div class="flow-num" id="f6">6</div><div><span class="highlight">Sales Bot</span> (LLM) negotiates with buyer agent — real prices, discounts, deal terms</div></div>
    <div class="flow-arrow">|</div>
    <div class="flow-step"><div class="flow-num" id="f7">7</div><div>Agreement reached — <span class="highlight">structured deal</span> returned (provider, rate, savings, contract)</div></div>
  </div>

  <div>
    <h2>Protocol Details</h2>
    <div class="proto-box">Frame: 52-byte header
  version (1B) + type (1B)
  + flags (2B) + passport_hash (16B)
  + sequence (4B) + timestamp (8B)
  + payload_length (4B)

Payload: MessagePack (binary)
Signature: Ed25519 (64 bytes)
Handshake: X25519 Diffie-Hellman
Encryption: XSalsa20-Poly1305
Trust: 10-check pipeline (0.0-1.0)</div>
  </div>

  <div>
    <h2>The Three Agents</h2>
    <div class="agent-box bp">
      <div class="agent-label">Border Police</div>
      Security gate. Checks passport, gives VERIFIED/REJECTED verdict. 1-2 turns, then hands off. Does NOT make security decisions — those are hardcoded crypto checks. The LLM just communicates the result.
    </div>
    <div class="agent-box sales">
      <div class="agent-label">Sales Bot</div>
      Negotiator behind the border. Has a real provider catalog with prices, discounts, and contract terms. Negotiates like a human salesperson — prompt payment discounts, loyalty deals, excess trade-offs.
    </div>
    <div class="agent-box buyer">
      <div class="agent-label">Buyer Agent (Your Agent)</div>
      Represents you. Takes your situation (what you pay now, what you want) and negotiates on your behalf. Pushes for discounts, compares offers, closes or walks away.
    </div>
  </div>

  <div>
    <h2>Why This Matters</h2>
    <p>Current AI agents talk to <em>humans</em> or call <em>APIs</em>. This shows agents talking to <em>each other</em> — with identity verification, encrypted channels, and structured outcomes. No human in the loop during negotiation.</p>
    <p style="margin-top:6px;" class="dim">Every message is powered by a separate LLM call (Groq llama-3.3-70b or local Ollama). The agents have different system prompts, different goals, and negotiate independently.</p>
  </div>

  <div>
    <h2>System Status</h2>
    <p>
      Backend API: <span class="status-badge" id="statusApi"><span class="status-dot"></span> checking...</span><br>
      Border Police: <span class="status-badge" id="statusBp"><span class="status-dot"></span> checking...</span><br>
      LLM: <span class="status-badge" id="statusLlm"><span class="status-dot"></span> checking...</span>
    </p>
  </div>
</div>

<!-- RIGHT: Chat Interface -->
<div class="chat-panel">
  <div class="chat-header">
    <h2><span class="status-dot"></span> Chat with Buyer Agent</h2>
    <div style="font-size:11px;color:#94a3b8;">Tell it what you need — it handles the rest</div>
  </div>
  <div class="chat-area" id="chatArea">
    <div class="chat-messages" id="chatMessages">
      <div class="msg system">
        Say what you need in plain English. The agent will generate a passport, get verified, connect to the Sales Bot, and negotiate a deal for you.
      </div>
    </div>
  </div>
  <div class="suggestions" id="suggestions">
    <span class="suggestion" onclick="suggest(this)">Find me a better power deal</span>
    <span class="suggestion" onclick="suggest(this)">I need car insurance</span>
    <span class="suggestion" onclick="suggest(this)">I'm paying 50c/kWh, get me a better rate</span>
    <span class="suggestion" onclick="suggest(this)">Run the full demo</span>
  </div>
  <div style="padding:6px 20px 10px;display:flex;gap:6px;">
    <input type="text" id="chatInput" placeholder="e.g. 'I'm paying 50c per kWh, find me something cheaper'..."
           onkeydown="if(event.key==='Enter'&&!event.shiftKey)sendChat()">
    <button class="btn-send" id="sendBtn" onclick="sendChat()">Send</button>
  </div>
</div>

</div>

<script>
const chatMessages = document.getElementById('chatMessages');
const chatInput = document.getElementById('chatInput');
const sendBtn = document.getElementById('sendBtn');
let sending = false;
let lastDeal = null;

// Check system status
fetch('/status').then(r=>r.json()).then(d=>{
  const api = document.getElementById('statusApi');
  const bp = document.getElementById('statusBp');
  const llm = document.getElementById('statusLlm');
  api.className = 'status-badge live';
  api.innerHTML = '<span class="status-dot"></span> Connected';
  bp.className = d.border_police ? 'status-badge live' : 'status-badge off';
  bp.innerHTML = d.border_police ? `<span class="status-dot"></span> ${d.border_police}` : 'Offline';
  llm.className = d.groq_configured ? 'status-badge live' : 'status-badge off';
  llm.innerHTML = d.groq_configured ? '<span class="status-dot"></span> Groq (llama-3.3-70b)' : 'No API key';
}).catch(()=>{
  ['statusApi','statusBp','statusLlm'].forEach(id => {
    const el = document.getElementById(id);
    el.className = 'status-badge off';
    el.textContent = 'Offline';
  });
});

function highlightStep(n) {
  for (let i = 1; i <= 7; i++) {
    const el = document.getElementById('f' + i);
    if (el) el.className = i <= n ? 'flow-num active' : 'flow-num';
  }
}

function suggest(el) { chatInput.value = el.textContent; sendChat(); }

function esc(text) {
  const d = document.createElement('div');
  d.textContent = text;
  return d.innerHTML;
}

function addMsg(role, text, cls, html) {
  const div = document.createElement('div');
  div.className = `msg ${cls}`;
  if (html) {
    div.innerHTML = `<div class="role">${esc(role)}</div>${text}`;
  } else {
    div.innerHTML = `<div class="role">${esc(role)}</div>${esc(text)}`;
  }
  chatMessages.appendChild(div);
  chatMessages.parentElement.scrollTop = chatMessages.parentElement.scrollHeight;
}

function renderDealCard(deal) {
  let html = '<div class="deal-card">';
  html += '<h3>&#10003; Deal Negotiated</h3>';

  if (deal.provider) {
    html += `<div class="deal-row"><span class="deal-label">Provider</span><span class="deal-value">${esc(deal.provider)}</span></div>`;
  }
  if (deal.plan) {
    html += `<div class="deal-row"><span class="deal-label">Plan</span><span class="deal-value">${esc(deal.plan)}</span></div>`;
  }
  if (deal.rate) {
    html += `<div class="deal-row"><span class="deal-label">Rate</span><span class="deal-value">${(deal.rate*100).toFixed(1)}c/kWh</span></div>`;
  }
  if (deal.monthly) {
    html += `<div class="deal-row"><span class="deal-label">Monthly</span><span class="deal-value">$${deal.monthly.toFixed(2)}/month</span></div>`;
  }
  if (deal.contract_months) {
    html += `<div class="deal-row"><span class="deal-label">Contract</span><span class="deal-value">${deal.contract_months} months</span></div>`;
  }
  if (deal.saving_pct) {
    html += `<div class="deal-saving">Saving: ${deal.saving_pct.toFixed(1)}%</div>`;
  }
  if (deal.annual_saving) {
    html += `<div style="color:#81c784;font-size:13px;">~$${deal.annual_saving.toFixed(0)}/year saved</div>`;
  }

  if (deal.switch_ready) {
    html += `<button class="btn-confirm" onclick="confirmSwitch()">Confirm Switch</button>`;
  }
  html += '</div>';
  return html;
}

function renderTranscript(transcript) {
  let html = '<div class="transcript-box">';
  let lastPhase = '';

  transcript.forEach(t => {
    // Show phase separator on handoff
    if (t.phase === 'sales_bot' && lastPhase === 'border_police') {
      html += '<div class="transcript-msg handoff">--- HANDOFF TO SALES BOT ---</div>';
    }
    lastPhase = t.phase || '';

    let cls, label;
    if (t.role === 'border_police') {
      cls = 'bp';
      label = '<span class="phase-tag bp">Border Police</span>';
    } else if (t.role === 'sales_bot') {
      cls = 'sales';
      label = '<span class="phase-tag sales">Sales Bot</span>';
    } else {
      cls = 'da';
      const phaseTag = t.phase === 'sales_bot'
        ? '<span class="phase-tag buyer">Buyer Agent</span>'
        : '<span class="phase-tag buyer">Demo Agent</span>';
      label = phaseTag;
    }

    const llm = t.llm_model ? ` <span style="color:#5a6a8a;font-size:9px;">[${esc(t.llm_model)}]</span>` : '';
    html += `<div class="transcript-msg ${cls}">
      <div class="transcript-label">${label}${llm}</div>
      ${esc(t.message)}
    </div>`;
  });
  html += '</div>';
  return html;
}

function renderToolResult(tool, result) {
  addMsg(`Tool: ${tool}`, '', 'tool-call', false);

  if (result.error) {
    addMsg('Result', result.error, 'tool-result', false);
    highlightStep(0);
    return;
  }

  let html = '';

  // Highlight flow steps based on what completed
  if (result.steps) {
    const stepNames = result.steps.map(s => s.step);
    if (stepNames.includes('passport_generated')) highlightStep(1);
    if (stepNames.includes('passport_verified')) highlightStep(2);
    if (stepNames.includes('passport_approved')) highlightStep(3);
    if (stepNames.includes('handshake_complete')) highlightStep(4);
    if (stepNames.includes('border_police_verdict')) highlightStep(5);
    if (stepNames.includes('sales_bot_start')) highlightStep(6);
    if (stepNames.includes('deal_closed') || result.agreed_deal) highlightStep(7);
  }

  // Verification badge
  if (result.transcript && result.transcript.length > 0) {
    const firstBP = result.transcript.find(t => t.role === 'border_police');
    if (firstBP) {
      const verified = firstBP.verified !== false;
      const badgeCls = verified ? 'verified' : 'rejected';
      const badgeText = verified ? '&#10003; VERIFIED' : '&#10007; REJECTED';
      html += `<div class="verify-badge ${badgeCls}">${badgeText}</div>`;
    }
  }

  // Checks display
  if (result.checks && Object.keys(result.checks).length > 0) {
    html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:3px;margin:4px 0;">';
    for (const [name, check] of Object.entries(result.checks)) {
      const icon = check.passed ? '&#10003;' : '&#10007;';
      const cls = check.passed ? 'color:#69f0ae' : 'color:#ff5252';
      html += `<div style="font-size:10px;${cls}">${icon} ${esc(name)}</div>`;
    }
    html += '</div>';
  }

  // Transcript display (with phase indicators)
  if (result.transcript && result.transcript.length > 0) {
    html += renderTranscript(result.transcript);
  }

  // Deal card
  if (result.agreed_deal) {
    lastDeal = result.agreed_deal;
    html += renderDealCard(result.agreed_deal);
  }

  // Generic fields (for non-negotiation tools)
  const skip = new Set(['checks','transcript','session_summary','steps','envelope_b64','agreed_deal','protocol_details','success','category']);
  const fields = Object.entries(result).filter(([k]) => !skip.has(k));
  if (fields.length > 0 && !html) {
    html = fields.map(([k,v]) => `<span style="color:#7a8ba8;font-size:11px;">${esc(k)}:</span> <span style="font-size:11px;">${esc(String(v))}</span>`).join('<br>');
  }

  if (html) {
    addMsg('Result', html, 'tool-result', true);
  }
}

async function confirmSwitch() {
  if (!lastDeal) return;
  const btn = event.target;
  btn.disabled = true;
  btn.textContent = 'Processing...';

  addMsg('You', 'Yes, go ahead and switch!', 'user');

  // Show typing indicator while "processing"
  const typing = document.createElement('div');
  typing.className = 'typing-indicator';
  typing.id = 'typingSwitch';
  typing.innerHTML = '<div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>';
  chatMessages.appendChild(typing);
  chatMessages.parentElement.scrollTop = chatMessages.parentElement.scrollHeight;

  await new Promise(r => setTimeout(r, 5000));

  const ti = document.getElementById('typingSwitch');
  if (ti) ti.remove();

  const provider = lastDeal.provider || 'the new provider';
  const plan = lastDeal.plan || 'your new plan';
  const confId = 'SW-' + Math.random().toString(36).substring(2, 8);
  const msg = `Done! Your account has been switched to ${provider} (${plan}).\n\nConfirmation ID: ${confId}\nYou should see the change reflected on your next billing cycle. If you have any issues, reference your confirmation ID with the provider.\n\nIs there anything else I can help with?`;

  addMsg('Demo Agent', msg, 'agent');
  btn.textContent = 'Switch Confirmed';
}

async function sendChat() {
  if (sending) return;
  const msg = chatInput.value.trim();
  if (!msg) return;
  chatInput.value = '';
  addMsg('You', msg, 'user');

  sending = true;
  sendBtn.disabled = true;
  sendBtn.innerHTML = '<span class="spinner"></span>';

  document.getElementById('suggestions').style.display = 'none';

  // Show typing indicator
  const typing = document.createElement('div');
  typing.className = 'typing-indicator';
  typing.id = 'typingIndicator';
  typing.innerHTML = '<div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>';
  chatMessages.appendChild(typing);
  chatMessages.parentElement.scrollTop = chatMessages.parentElement.scrollHeight;

  try {
    const resp = await fetch('/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message: msg}),
    });
    const data = await resp.json();

    // Remove typing indicator
    const ti = document.getElementById('typingIndicator');
    if (ti) ti.remove();

    if (data.tool_results && data.tool_results.length > 0) {
      data.tool_results.forEach(tr => renderToolResult(tr.tool, tr.result));
    }

    if (data.reply) {
      addMsg('Demo Agent', data.reply, 'agent');
    }

  } catch (e) {
    const ti = document.getElementById('typingIndicator');
    if (ti) ti.remove();
    addMsg('System', `Error: ${e.message}`, 'system');
  }

  sending = false;
  sendBtn.disabled = false;
  sendBtn.innerHTML = 'Send';
  chatInput.focus();
}
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return CHAT_HTML


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "3100"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
