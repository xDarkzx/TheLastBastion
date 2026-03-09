import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowUpRight, Send, RotateCcw, Shield, MessageSquare, Zap, Users } from 'lucide-react';
import { demoService } from '../../services/api';

/* ── tiny helpers ── */
const esc = (t) => { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; };

const QUIRKY_MESSAGES = [
  // Sci-fi & movies
  "Starting the flux capacitor...",
  "Powering up the nuclear reactor...",
  "Reversing the polarity of the neutron flow...",
  "Entering the Matrix... finding the best deal...",
  "Using the Force to find discounts...",
  "Activating Skynet... but the friendly version...",
  "Channeling Doc Brown energy...",
  "Warming up the warp drive...",
  "Locking S-foils in attack position...",
  "Engaging ludicrous speed...",
  "Routing through the Upside Down...",
  "Asking JARVIS for a second opinion...",
  "Opening a portal to the discount dimension...",
  "Reconfiguring the deflector dish...",
  "This isn't the price you're looking for...",
  "I'll be back... with a better offer...",
  "Hasta la vista, overpriced plans...",
  "Beam me up a better deal, Scotty...",
  "Morpheus said follow the white rabbit of savings...",
  "Taking the red pill... prices are not what they seem...",
  "Houston, we have a negotiation...",
  "To infinity and beyond... but within budget...",
  "Fly, you fools... to cheaper providers...",
  "One does not simply walk into a bad deal...",
  "We're gonna need a bigger discount...",
  "I see dead prices... and they're too high...",
  "With great savings comes great responsibility...",
  "Winter is coming... lock in your rate now...",
  "May the odds be ever in your favour...",
  "I am Groot... and I found you a deal...",
  "Wakanda forever... or at least 24 months...",

  // Tech & hacking
  "Hacking the mainframe... legally...",
  "Calibrating the quantum entanglement matrix...",
  "Downloading more RAM for negotiations...",
  "Clearing the browser cookies of destiny...",
  "Running negotiations.exe...",
  "sudo get-better-deal --force...",
  "Stack overflow: too many good deals found...",
  "Deploying Kubernetes pods of persuasion...",
  "git push --force savings to your account...",
  "npm install better-prices@latest...",
  "Compiling 47 million lines of deal code...",
  "Defragmenting the price database...",
  "Rebooting the deal-finding subroutine...",
  "Injecting SQL into the discount table... ethically...",
  "Converting your request to binary and back again...",
  "Running on 100% renewable sarcasm...",
  "AI is thinking... which is more than some companies do...",

  // Spy & secret agent
  "Activating sleeper agent protocols...",
  "Agent is going undercover in the sales department...",
  "Establishing a secure channel to the shadow realm...",
  "The name's Bot... Deal Bot...",
  "Shaking, not stirring, the negotiations...",
  "Mission: Impossible — finding a fair price...",
  "Infiltrating the provider's secret price list...",
  "Your mission, should you choose to accept it...",
  "Deploying smoke screen while we negotiate...",
  "The eagle has landed... at a competitive rate...",

  // Food & drink
  "Converting caffeine into discount codes...",
  "Brewing a fresh pot of negotiation juice...",
  "Marinating the deal in savings sauce...",
  "Adding a pinch of leverage and a dash of charm...",
  "Baking a fresh batch of competitive quotes...",
  "Taste-testing the offers... this one's spicy...",
  "Putting the deal in the oven at 180 degrees...",
  "Seasoning the contract with consumer rights...",

  // Animals & nature
  "Teaching a parrot to say 'give me a discount'...",
  "Unleashing the negotiation honey badger...",
  "Herding cats toward a better deal...",
  "Releasing the savings kraken...",
  "Consulting the wisdom of the deal-finding owl...",
  "Sending carrier pigeons to competing providers...",
  "The early bird gets the best rate...",

  // Office & corporate
  "Putting on the agent's negotiation pants...",
  "Polishing the agent's monocle...",
  "Scheduling a meeting with the discount committee...",
  "Filing form 27B-stroke-6 for price reduction...",
  "Taking the elevator to the penthouse of savings...",
  "Warming up the PowerPoint of persuasion...",
  "Consulting the ancient spreadsheets of pricing...",
  "Running sentiment analysis on the sales bot's mood...",
  "Checking if Mercury is in retrograde first...",
  "Reading the terms and conditions... all 47 pages...",
  "Bypassing corporate jargon filters...",
  "Translating human desperation into machine leverage...",
  "Negotiating at the speed of bureaucracy...",

  // Gaming
  "Loading save file... last checkpoint: good deal...",
  "Entering cheat code: UP UP DOWN DOWN DISCOUNT...",
  "Boss fight: Final Price vs Your Budget...",
  "Achievement unlocked: found a provider who answers...",
  "Rolling a D20 for negotiation check... nat 20!...",
  "Speedrunning the comparison engine...",
  "Player 2 has entered the negotiation...",
  "Glitching through the paywall...",

  // Misc quirky
  "Asking the magic 8-ball for guidance...",
  "Checking if the vibes are right...",
  "Summoning the deal gods...",
  "Reverse-engineering the fine print...",
  "Triangulating the optimal price point...",
  "Recalibrating the BS detector...",
  "Bribing the border guards... just kidding...",
  "Whispering sweet nothings to the API...",
  "Encrypting your hopes and dreams...",
  "Uploading your vibe check results...",
  "Crossing fingers, toes, and neural pathways...",
  "Doing the maths so you don't have to...",
  "Applying quantum discount theory...",
  "Assembling the Avengers of savings...",
  "Shaking the magic money tree...",
  "Consulting the Oracle... she says wait...",
  "Asking ChatGPT... just kidding, we're better...",
  "Counting sheep while the servers think...",
  "Folding space-time to skip the queue...",
  "Manifesting savings through positive vibes...",
  "Putting your request in a bottle and throwing it...",
  "Sending thoughts and prayers to the pricing engine...",
  "Building IKEA furniture while we wait...",
  "Solving world peace... or at least your bill...",
  "Googling 'how to negotiate' just to double-check...",
  "Pretending to walk away to get a better offer...",
  "Making the sales bot an offer it can't refuse...",
  "Applying the puppy dog eyes algorithm...",
  "Calculating the meaning of a good deal... it's 42...",
];

const DemoAgentView = () => {
  const navigate = useNavigate();
  const [messages, setMessages] = useState([
    { role: 'system', text: 'Say what you need in plain English. The agent will generate a passport, get verified, connect to the Sales Bot, and negotiate a deal for you.' }
  ]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [negotiating, setNegotiating] = useState(false);
  const [quirkIndex, setQuirkIndex] = useState(0);
  const [status, setStatus] = useState(null);
  const [activeStep, setActiveStep] = useState(0);
  const chatEndRef = useRef(null);

  // Rotate quirky messages every 3s while negotiating
  useEffect(() => {
    if (!negotiating) return;
    setQuirkIndex(Math.floor(Math.random() * QUIRKY_MESSAGES.length));
    const interval = setInterval(() => {
      setQuirkIndex(prev => {
        let next;
        do { next = Math.floor(Math.random() * QUIRKY_MESSAGES.length); } while (next === prev);
        return next;
      });
    }, 5000);
    return () => clearInterval(interval);
  }, [negotiating]);

  useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  useEffect(() => {
    demoService.getStatus().then(r => setStatus(r.data)).catch(() => {});
  }, []);

  const suggestions = [
    'Find me a better power deal',
    'I need car insurance',
    "I'm paying 50c/kWh, get me a better rate",
    'Run the full demo',
  ];

  const highlightStep = (n) => setActiveStep(n);

  const processToolResults = (data) => {
    if (data.tool_results?.length) {
      data.tool_results.forEach(tr => {
        const result = tr.result;
        if (result.steps) {
          const names = result.steps.map(s => s.step);
          if (names.includes('passport_generated')) highlightStep(1);
          if (names.includes('passport_verified')) highlightStep(2);
          if (names.includes('passport_approved')) highlightStep(3);
          if (names.includes('handshake_complete')) highlightStep(4);
          if (names.includes('border_police_verdict')) highlightStep(5);
          if (names.includes('sales_bot_start')) highlightStep(6);
          if (names.includes('deal_closed') || result.agreed_deal) highlightStep(7);
        }
        setMessages(prev => [...prev, { role: 'tool-call', text: `Tool: ${tr.tool}` }]);
        setMessages(prev => [...prev, { role: 'tool-result', result }]);
      });
    }
    if (data.reply) {
      setMessages(prev => [...prev, { role: 'agent', text: data.reply }]);
    }
  };

  // Fake typing delay — makes instant responses feel natural
  const fakeTypingDelay = (text) => {
    // Longer messages get slightly longer delays (1s base + up to 1.5s)
    const base = 1000;
    const extra = Math.min(text.length * 8, 1500);
    const jitter = Math.random() * 500;
    return new Promise(resolve => setTimeout(resolve, base + extra + jitter));
  };

  const sendMessage = async (text) => {
    const msg = (text || input).trim();
    if (!msg || sending) return;
    setInput('');
    setMessages(prev => [...prev, { role: 'user', text: msg }]);
    setSending(true);

    try {
      const { data } = await demoService.chat(msg);

      // Two-phase flow: chat returns instantly with a natural reply,
      // then we call /negotiate separately for the long-running part
      if (data.action === 'negotiate') {
        // Brief typing pause before showing the natural reply
        await fakeTypingDelay(data.reply);
        setMessages(prev => [...prev, { role: 'agent', text: data.reply }]);

        // Phase 2: Run negotiation in the background with quirky status
        setNegotiating(true);
        try {
          const { data: negData } = await demoService.negotiate(data.category, data.user_context || msg);
          processToolResults(negData);
        } catch (negErr) {
          setMessages(prev => [...prev, { role: 'system', text: `Negotiation error: ${negErr.message}` }]);
        } finally {
          setNegotiating(false);
        }
      } else {
        // Normal chat — add typing delay before showing reply
        if (data.tool_results?.length) {
          processToolResults(data);
        } else if (data.reply) {
          await fakeTypingDelay(data.reply);
          setMessages(prev => [...prev, { role: 'agent', text: data.reply }]);
        }
      }
    } catch (e) {
      setMessages(prev => [...prev, { role: 'system', text: `Error: ${e.message}` }]);
    }
    setSending(false);
  };

  const resetChat = async () => {
    await demoService.reset().catch(() => {});
    setMessages([{ role: 'system', text: 'Conversation reset. Say what you need.' }]);
    setActiveStep(0);
  };

  return (
    <div className="h-screen bg-white flex flex-col overflow-hidden" style={{ fontFamily: "'Outfit', 'Inter', system-ui, sans-serif" }}>
      {/* Nav */}
      <nav className="sticky top-0 z-50 bg-white/90 backdrop-blur-md border-b border-slate-100">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => navigate('/')}>
            <img src="/TheRegistryBase.png" alt="The Last Bastion" className="w-12 h-12 object-contain" />
            <span className="text-base font-bold tracking-tight text-slate-900">The Last Bastion</span>
          </div>
          <div className="hidden md:flex items-center gap-8">
            <button onClick={() => navigate('/')} className="text-[13px] text-slate-500 hover:text-slate-900 transition-colors font-medium">Home</button>
            <span className="text-[13px] text-slate-900 font-semibold">Live Agent Demo</span>
          </div>
          <button onClick={() => navigate('/dashboard')}
            className="px-5 py-2 bg-slate-900 hover:bg-slate-800 text-white text-[12px] font-semibold tracking-wide rounded-md transition-colors flex items-center gap-2">
            Command Center <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </nav>

      {/* Main content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left panel — info */}
        <aside className="w-[380px] min-w-[380px] bg-slate-50 border-r border-slate-200 overflow-y-auto p-5 hidden lg:flex flex-col gap-4">
          <div>
            <h1 className="text-base font-bold text-slate-900 mb-1">Agent-to-Agent Trading Demo</h1>
            <p className="text-xs text-slate-500 leading-relaxed">A working demo of how AI agents could negotiate real-world deals through an authenticated, encrypted channel.</p>
          </div>

          <div>
            <h2 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">What You're Seeing</h2>
            <p className="text-xs text-slate-500 leading-relaxed">Two independent LLM agents talking to each other over a <span className="font-semibold text-slate-700">custom binary protocol</span>. One represents you (the buyer). The other is a sales bot behind a security perimeter.</p>
          </div>

          <div>
            <h2 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">Communication Flow</h2>
            {[
              'Buyer agent generates an Ed25519 cryptographic passport',
              'Passport uploaded for 10-check verification',
              'Passport approved — agent now has a trust score',
              'TCP connection to Border Police — X25519 key exchange',
              'Border Police verifies passport, gives verdict, hands off',
              'Sales Bot negotiates with buyer agent — real prices & discounts',
              'Agreement reached — structured deal returned',
            ].map((step, i) => (
              <div key={i} className="flex items-start gap-2.5 py-1">
                <div className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0 ${
                  i < activeStep ? 'bg-green-100 text-green-600' : 'bg-slate-200 text-slate-500'
                }`}>{i + 1}</div>
                <span className="text-[11px] text-slate-500 leading-snug">{step}</span>
              </div>
            ))}
          </div>

          <div>
            <h2 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">The Three Agents</h2>
            <div className="bg-blue-50 border-l-2 border-blue-400 rounded p-2 mb-1.5">
              <div className="text-[9px] font-bold text-blue-500 uppercase tracking-wider">Border Police</div>
              <div className="text-[11px] text-slate-600">Security gate. Checks passport, gives VERIFIED/REJECTED verdict.</div>
            </div>
            <div className="bg-purple-50 border-l-2 border-purple-400 rounded p-2 mb-1.5">
              <div className="text-[9px] font-bold text-purple-500 uppercase tracking-wider">Sales Bot</div>
              <div className="text-[11px] text-slate-600">Negotiator behind the border. Real provider catalog with prices and discounts.</div>
            </div>
            <div className="bg-green-50 border-l-2 border-green-400 rounded p-2">
              <div className="text-[9px] font-bold text-green-500 uppercase tracking-wider">Buyer Agent (Your Agent)</div>
              <div className="text-[11px] text-slate-600">Represents you. Negotiates on your behalf — pushes for discounts, compares offers.</div>
            </div>
          </div>

          <div>
            <h2 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">Protocol Details</h2>
            <div className="bg-slate-100 border border-slate-200 rounded-lg p-2.5 font-mono text-[10px] text-slate-500 leading-relaxed whitespace-pre">{`Frame: 52-byte header
  version (1B) + type (1B)
  + flags (2B) + passport_hash (16B)
  + sequence (4B) + timestamp (8B)
  + payload_length (4B)

Payload: MessagePack (binary)
Signature: Ed25519 (64 bytes)
Handshake: X25519 Diffie-Hellman
Encryption: XSalsa20-Poly1305
Trust: 10-check pipeline (0.0-1.0)`}</div>
          </div>

          {status && (
            <div>
              <h2 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">System Status</h2>
              <div className="space-y-1 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">Backend API:</span>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-green-100 text-green-600">Connected</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">Border Police:</span>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${status.border_police ? 'bg-green-100 text-green-600' : 'bg-red-50 text-red-500'}`}>
                    {status.border_police || 'Offline'}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">LLM:</span>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${status.groq_configured ? 'bg-green-100 text-green-600' : 'bg-red-50 text-red-500'}`}>
                    {status.groq_configured ? 'Groq (llama-3.3-70b)' : 'No API key'}
                  </span>
                </div>
              </div>
            </div>
          )}
        </aside>

        {/* Right panel — chat */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Chat header */}
          <div className="px-5 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              <h2 className="text-sm font-semibold text-slate-900">Chat with Buyer Agent</h2>
              <span className="text-[11px] text-slate-400 ml-2">Tell it what you need — it handles the rest</span>
            </div>
            <button onClick={resetChat} className="text-slate-400 hover:text-slate-600 transition-colors p-1.5 rounded hover:bg-slate-100" title="Reset conversation">
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-5">
            <div className="max-w-[700px] flex flex-col gap-2">
              {messages.map((msg, i) => (
                <MessageBubble key={i} msg={msg} />
              ))}
              {sending && !negotiating && (
                <div className="flex items-center gap-1.5 px-3.5 py-2.5 bg-slate-100 border border-slate-200 rounded-lg self-start max-w-[80px]">
                  <div className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce" style={{ animationDelay: '0ms' }} />
                  <div className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce" style={{ animationDelay: '150ms' }} />
                  <div className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce" style={{ animationDelay: '300ms' }} />
                </div>
              )}
              {negotiating && (
                <div className="self-start flex items-center gap-2.5 px-4 py-2.5 bg-slate-100 border border-slate-200 rounded-lg">
                  <div className="flex items-center gap-1">
                    <div className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce" style={{ animationDelay: '0ms' }} />
                    <div className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce" style={{ animationDelay: '150ms' }} />
                    <div className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce" style={{ animationDelay: '300ms' }} />
                  </div>
                  <span className="text-[12px] text-slate-500 italic">{QUIRKY_MESSAGES[quirkIndex]}</span>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>
          </div>

          {/* Suggestions */}
          {messages.length <= 1 && (
            <div className="flex gap-2 px-5 pb-2 flex-wrap">
              {suggestions.map(s => (
                <button key={s} onClick={() => sendMessage(s)}
                  className="px-3 py-1.5 bg-white border border-slate-200 rounded-full text-[11px] text-slate-500 hover:border-blue-400 hover:text-blue-500 transition-colors">
                  {s}
                </button>
              ))}
            </div>
          )}

          {/* Input */}
          <div className="px-5 py-3 border-t border-slate-100 flex gap-2">
            <input
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendMessage()}
              placeholder="e.g. 'I'm paying 50c per kWh, find me something cheaper'..."
              className="flex-1 px-4 py-2.5 bg-white border border-slate-200 rounded-lg text-sm text-slate-900 outline-none focus:border-blue-400 transition-colors"
              disabled={sending}
            />
            <button onClick={() => sendMessage()} disabled={sending || !input.trim()}
              className="px-4 py-2.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5">
              <Send className="w-3.5 h-3.5" /> Send
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

/* ── Message bubble renderer ── */
const MessageBubble = ({ msg }) => {
  if (msg.role === 'system') {
    return (
      <div className="self-center text-center px-4 py-2 bg-slate-50 border border-slate-100 rounded-lg text-[11px] text-slate-400 max-w-full">
        {msg.text}
      </div>
    );
  }

  if (msg.role === 'user') {
    return (
      <div className="self-end px-3 py-2 bg-slate-900 text-white rounded-lg text-[13px] leading-relaxed max-w-[95%]">
        <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-0.5">You</div>
        {msg.text}
      </div>
    );
  }

  if (msg.role === 'agent') {
    return (
      <div className="self-start px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-[13px] text-slate-700 leading-relaxed max-w-[95%] whitespace-pre-wrap">
        <div className="text-[10px] font-semibold text-blue-500 uppercase tracking-wider mb-0.5">Demo Agent</div>
        {msg.text}
      </div>
    );
  }

  if (msg.role === 'tool-call') {
    return (
      <div className="self-start px-3 py-2 bg-purple-50 border border-purple-200 border-l-[3px] border-l-purple-500 rounded-lg text-[11px] text-purple-700 font-mono max-w-full">
        <div className="text-[10px] font-semibold text-purple-500 uppercase tracking-wider mb-0.5">Tool Call</div>
        {msg.text}
      </div>
    );
  }

  if (msg.role === 'tool-result' && msg.result) {
    return <ToolResultBubble result={msg.result} />;
  }

  return null;
};

/* ── Tool result renderer ── */
const ToolResultBubble = ({ result }) => {
  // Verification badge
  const firstBP = result.transcript?.find(t => t.role === 'border_police');
  const verified = firstBP ? firstBP.verified !== false : null;

  return (
    <div className="self-start px-3 py-2 bg-green-50 border border-green-200 border-l-[3px] border-l-green-500 rounded-lg text-[11px] font-mono max-w-full">
      <div className="text-[10px] font-semibold text-green-600 uppercase tracking-wider mb-1">Result</div>

      {verified !== null && (
        <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold mb-2 ${
          verified ? 'bg-green-100 text-green-600 border border-green-200' : 'bg-red-50 text-red-500 border border-red-200'
        }`}>
          {verified ? '\u2713 VERIFIED' : '\u2717 REJECTED'}
        </span>
      )}

      {/* Checks grid */}
      {result.checks && Object.keys(result.checks).length > 0 && (
        <div className="grid grid-cols-2 gap-1 my-1.5">
          {Object.entries(result.checks).map(([name, check]) => (
            <div key={name} className={`text-[10px] ${check.passed ? 'text-green-600' : 'text-red-500'}`}>
              {check.passed ? '\u2713' : '\u2717'} {name}
            </div>
          ))}
        </div>
      )}

      {/* Transcript */}
      {result.transcript?.length > 0 && (
        <div className="mt-2 p-2 bg-slate-50 rounded border border-slate-200">
          {result.transcript.map((t, i) => {
            const prev = i > 0 ? result.transcript[i - 1] : null;
            const showHandoff = t.phase === 'sales_bot' && prev?.phase === 'border_police';
            const cls = t.role === 'border_police' ? 'bg-blue-50 border-l-blue-400'
              : t.role === 'sales_bot' ? 'bg-purple-50 border-l-purple-400'
              : 'bg-green-50 border-l-green-400';
            const labelCls = t.role === 'border_police' ? 'text-blue-500'
              : t.role === 'sales_bot' ? 'text-purple-500' : 'text-green-500';
            const label = t.role === 'border_police' ? 'Border Police'
              : t.role === 'sales_bot' ? 'Sales Bot'
              : t.phase === 'sales_bot' ? 'Buyer Agent' : 'Demo Agent';

            return (
              <React.Fragment key={i}>
                {showHandoff && (
                  <div className="text-center text-[10px] font-semibold text-amber-600 bg-amber-50 border-l-2 border-amber-400 rounded px-2 py-1 my-1">
                    --- HANDOFF TO SALES BOT ---
                  </div>
                )}
                <div className={`px-2 py-1 my-0.5 rounded border-l-2 ${cls} text-[11px] text-slate-600`}>
                  <div className={`text-[9px] font-bold uppercase tracking-wider ${labelCls}`}>
                    {label}
                    {t.llm_model && <span className="text-slate-400 font-normal ml-1">[{t.llm_model}]</span>}
                  </div>
                  {t.message}
                </div>
              </React.Fragment>
            );
          })}
        </div>
      )}

      {/* Deal card */}
      {result.agreed_deal && <DealCard deal={result.agreed_deal} category={result.category} />}

      {/* Generic fields fallback */}
      {!result.transcript?.length && !result.agreed_deal && !result.checks && (
        <div className="text-slate-600">
          {Object.entries(result)
            .filter(([k]) => !['checks','transcript','session_summary','steps','envelope_b64','agreed_deal','protocol_details','success','category'].includes(k))
            .map(([k, v]) => (
              <div key={k}><span className="text-slate-400">{k}:</span> {String(v)}</div>
            ))}
        </div>
      )}
    </div>
  );
};

/* ── Deal card ── */
const DealCard = ({ deal, category }) => {
  const isPower = category === 'power' || (!category && deal.rate && deal.rate < 1);
  return (
    <div className="mt-2 p-3 rounded-lg bg-gradient-to-br from-green-50 to-green-100 border border-green-200">
      <h3 className="text-green-600 font-bold text-[13px] mb-2">
        {'\u2713'} {isPower ? 'Power' : 'Insurance'} Deal Negotiated
      </h3>
      {deal.provider && <Row label="Provider" value={deal.provider} />}
      {deal.plan && <Row label="Plan" value={deal.plan} />}
      {isPower && deal.rate != null && <Row label="Rate" value={`${(deal.rate * 100).toFixed(1)}c/kWh`} />}
      {!isPower && (deal.monthly || deal.rate) && <Row label="Monthly" value={`$${(deal.monthly || deal.rate).toFixed(2)}/month`} />}
      {isPower && deal.monthly != null && <Row label="Monthly" value={`$${deal.monthly.toFixed(2)}/month`} />}
      {deal.deductible != null && <Row label="Deductible" value={`$${deal.deductible}`} />}
      {deal.contract_months && <Row label="Contract" value={`${deal.contract_months} months`} />}
      {deal.saving_pct != null && <div className="text-green-600 text-base font-bold mt-1.5">Saving: {deal.saving_pct.toFixed(1)}%</div>}
      {deal.annual_saving != null && <div className="text-green-500 text-[13px]">~${deal.annual_saving.toFixed(0)}/year saved</div>}
    </div>
  );
};

const Row = ({ label, value }) => (
  <div className="flex justify-between py-0.5 text-xs">
    <span className="text-slate-500">{label}</span>
    <span className="text-slate-900 font-semibold">{value}</span>
  </div>
);

export default DemoAgentView;
