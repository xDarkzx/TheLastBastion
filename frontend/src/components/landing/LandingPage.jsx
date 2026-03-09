import React, { useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, useInView, useScroll, useTransform } from 'framer-motion';
import {
  Shield, Bot, Fingerprint, Globe,
  CheckCircle, Lock, Database,
  ArrowRight, Eye, Network,
  Layers, Hexagon, GitBranch, FileText,
  ArrowUpRight, AlertTriangle, ExternalLink
} from 'lucide-react';

/* ─── Fade-in on scroll ─── */
const FadeIn = ({ children, className = '', delay = 0 }) => {
  const ref = useRef(null);
  const isInView = useInView(ref, { once: true, margin: '-60px' });
  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 24 }}
      animate={isInView ? { opacity: 1, y: 0 } : { opacity: 0, y: 24 }}
      transition={{ duration: 0.5, delay, ease: [0.25, 0.4, 0.25, 1] }}
      className={className}
    >
      {children}
    </motion.div>
  );
};

/* ─── Source citation link ─── */
const Source = ({ href, label }) => (
  <a href={href} target="_blank" rel="noopener noreferrer"
    className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-600 transition-colors font-medium">
    {label} <ExternalLink className="w-2.5 h-2.5" />
  </a>
);

/* ═══════════════════════════════════════════════
   LANDING PAGE
   ═══════════════════════════════════════════════ */
const LandingPage = () => {
  const navigate = useNavigate();
  const { scrollYProgress } = useScroll();
  const headerShadow = useTransform(
    scrollYProgress, [0, 0.02],
    ['0 0 0 0 rgba(0,0,0,0)', '0 1px 3px 0 rgba(0,0,0,0.08)']
  );

  return (
    <div className="min-h-screen bg-white text-slate-900 overflow-x-hidden" style={{ fontFamily: "'Outfit', 'Inter', system-ui, sans-serif" }}>

      {/* ═══════ NAV ═══════ */}
      <motion.nav
        className="fixed top-0 left-0 right-0 z-50 bg-white/90 backdrop-blur-md border-b border-slate-100"
        style={{ boxShadow: headerShadow }}
      >
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img src="/TheRegistryBase.png" alt="The Last Bastion" className="w-12 h-12 object-contain" />
            <span className="text-base font-bold tracking-tight text-slate-900">The Last Bastion</span>
          </div>
          <div className="hidden md:flex items-center gap-8">
            <a href="#problem" className="text-[13px] text-slate-500 hover:text-slate-900 transition-colors font-medium">The Problem</a>
            <a href="#missions" className="text-[13px] text-slate-500 hover:text-slate-900 transition-colors font-medium">What We Do</a>
            <a href="#why" className="text-[13px] text-slate-500 hover:text-slate-900 transition-colors font-medium">Why Independent</a>
            <a href="#technology" className="text-[13px] text-slate-500 hover:text-slate-900 transition-colors font-medium">Technology</a>
            <button onClick={() => navigate('/demo')} className="text-[13px] text-slate-500 hover:text-slate-900 transition-colors font-medium">Live Agent Demo</button>
          </div>
          <button
            onClick={() => navigate('/dashboard')}
            className="px-5 py-2 bg-slate-900 hover:bg-slate-800 text-white text-[12px] font-semibold tracking-wide rounded-md transition-colors flex items-center gap-2"
          >
            Command Center <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </motion.nav>

      {/* ═══════ HERO ═══════ */}
      <section className="pt-32 pb-16 md:pt-40 md:pb-24 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-slate-50 border border-slate-200 mb-8"
          >
            <span className="text-[11px] text-slate-500 font-semibold tracking-wide">
              Built on A2A Protocol &middot; Blockchain-Anchored Proofs
            </span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="text-4xl md:text-6xl lg:text-[4.2rem] font-bold tracking-tight leading-[1.1] mb-6 text-slate-900"
          >
            As agents begin to act on our behalf,{' '}
            <span className="text-slate-400">someone needs to make sure they're telling the truth.</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="text-lg md:text-xl text-slate-500 max-w-2xl mx-auto mb-10 leading-relaxed"
          >
            The Last Bastion is working toward becoming a neutral, independent verification
            layer for the machine-to-machine economy — a place where agents prove who they are
            and what they carry, verified by protocol and cryptography rather than any single corporation.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-14"
          >
            <button
              onClick={() => navigate('/dashboard')}
              className="group px-7 py-3 bg-slate-900 hover:bg-slate-800 text-white rounded-md font-semibold text-[13px] tracking-wide transition-all flex items-center gap-2"
            >
              See The Live System
              <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
            </button>
            <a
              href="#problem"
              className="px-7 py-3 bg-white hover:bg-slate-50 border border-slate-200 rounded-md font-semibold text-[13px] tracking-wide transition-all text-slate-600 hover:text-slate-900"
            >
              Why This Matters
            </a>
          </motion.div>

          {/* Market context — real numbers with sources */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.4 }}
            className="inline-flex flex-col items-center gap-3"
          >
            <div className="flex items-center gap-6 md:gap-10 px-6 py-4 bg-slate-50 rounded-lg border border-slate-100">
              <div className="text-center">
                <div className="text-xl md:text-2xl font-bold text-slate-900 font-mono">$201.9B</div>
                <div className="text-[10px] text-slate-400 font-medium mt-0.5">Agentic AI spend in 2026</div>
              </div>
              <div className="w-px h-8 bg-slate-200" />
              <div className="text-center">
                <div className="text-xl md:text-2xl font-bold text-slate-900 font-mono">40%</div>
                <div className="text-[10px] text-slate-400 font-medium mt-0.5">Enterprise apps with agents by EOY</div>
              </div>
              <div className="w-px h-8 bg-slate-200" />
              <div className="text-center">
                <div className="text-xl md:text-2xl font-bold text-slate-900 font-mono">100+</div>
                <div className="text-[10px] text-slate-400 font-medium mt-0.5">Companies backing A2A protocol</div>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <Source href="https://onereach.ai/blog/agentic-ai-adoption-rates-roi-market-trends/" label="Gartner 2026" />
              <Source href="https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/" label="A2A Protocol" />
              <Source href="https://www.nist.gov/caisi/ai-agent-standards-initiative" label="NIST Agent Standards" />
            </div>
          </motion.div>
        </div>
      </section>

      {/* ═══════ THE PROBLEM ═══════ */}
      <section id="problem" className="py-20 md:py-28 px-6 bg-slate-50 border-y border-slate-100">
        <div className="max-w-5xl mx-auto">
          <FadeIn className="text-center mb-14">
            <p className="text-[12px] font-semibold text-slate-400 uppercase tracking-widest mb-3">The Problem</p>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-5">
              Platforms are doing great work building agents.<br />
              <span className="text-slate-400">But who watches the watchers?</span>
            </h2>
            <p className="text-base text-slate-500 max-w-2xl mx-auto leading-relaxed">
              When agents operate within a single platform, that platform can vouch for them.
              But when an agent from one ecosystem needs to trust an agent from another,
              there's a gap. The Cloud Security Alliance calls this
              {' '}<span className="text-slate-700 font-medium">"the three-party identity gap"</span>{' '}
              — and it's a problem nobody set out to create. It just emerged as the ecosystem grew.
            </p>
          </FadeIn>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {[
              {
                icon: Bot,
                title: 'Agent identity spoofing',
                desc: 'Researchers have identified "agent identity spoofing" and "capability declaration forgery" as systemic cross-protocol vulnerabilities affecting MCP, A2A, Agora, and ANP protocols.',
                source: { label: 'HelpNetSecurity', href: 'https://www.helpnetsecurity.com/2026/03/05/securing-autonomous-ai-agents/' },
              },
              {
                icon: Network,
                title: 'Trust graph attacks',
                desc: 'If Agent A trusts Agent B, and Agent B trusts Agent C, a compromised Agent C can manipulate Agent A through the chain. This cascading trust failure is amplified because agent decision-making is probabilistic, making detection extraordinarily difficult.',
                source: { label: 'Adversa AI', href: 'https://adversa.ai/blog/top-agentic-ai-security-resources-march-2026/' },
              },
              {
                icon: AlertTriangle,
                title: 'No cross-platform governance',
                desc: 'Without an independent oversight mechanism, cross-cloud agent interactions remain entirely ungoverned. NIST launched the AI Agent Standards Initiative in February 2026 specifically because this gap exists.',
                source: { label: 'NIST', href: 'https://www.nist.gov/caisi/ai-agent-standards-initiative' },
              },
            ].map((item, i) => (
              <FadeIn key={item.title} delay={i * 0.1}>
                <div className="bg-white p-7 rounded-lg border border-slate-200 hover:border-slate-300 transition-colors h-full flex flex-col">
                  <item.icon className="w-6 h-6 text-slate-400 mb-4" />
                  <h3 className="text-base font-bold mb-2 text-slate-900">{item.title}</h3>
                  <p className="text-sm text-slate-500 leading-relaxed flex-1 mb-4">{item.desc}</p>
                  <Source href={item.source.href} label={item.source.label} />
                </div>
              </FadeIn>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════ TWO MISSIONS ═══════ */}
      <section id="missions" className="py-20 md:py-28 px-6">
        <div className="max-w-5xl mx-auto">
          <FadeIn className="text-center mb-14">
            <p className="text-[12px] font-semibold text-slate-400 uppercase tracking-widest mb-3">What We Do</p>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-5">
              Two verification problems. One independent platform.
            </h2>
            <p className="text-base text-slate-500 max-w-2xl mx-auto leading-relaxed">
              The NIST AI Agent Standards Initiative and the emerging Know Your Agent (KYA) framework
              both identify the same needs: agent identity verification and data integrity assurance.
              We're building toward both — with every verdict recorded on an immutable ledger
              that we don't control and can't alter after the fact.
            </p>
          </FadeIn>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Mission 1 */}
            <FadeIn>
              <div className="bg-white p-8 rounded-lg border border-slate-200 hover:border-slate-300 transition-colors h-full">
                <div className="flex items-center gap-3 mb-5">
                  <div className="w-10 h-10 rounded-md bg-slate-50 border border-slate-100 flex items-center justify-center">
                    <Shield className="w-5 h-5 text-slate-600" />
                  </div>
                  <div>
                    <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Mission 1</div>
                    <h3 className="text-lg font-bold">Agent Trust Verification</h3>
                  </div>
                </div>
                <p className="text-sm text-slate-500 leading-relaxed mb-5">
                  Know Your Agent for the machine economy. Before an agent can participate
                  in our network, it proves its identity through cryptographic challenge-response,
                  demonstrates capability through historical evidence, and earns trust through
                  verified behavior over time — not through self-reported claims.
                </p>
                <div className="space-y-2">
                  {[
                    'Cryptographic identity verification (Ed25519 challenge-response)',
                    'Behavioral analysis from real protocol history',
                    'Anti-Sybil detection (key collision, URL reuse, registration bursts)',
                    'Progressive trust levels earned through verified actions',
                    'Trust passport anchored on-chain — queryable by any agent, anywhere',
                  ].map((item) => (
                    <div key={item} className="flex items-start gap-2">
                      <CheckCircle className="w-3.5 h-3.5 text-slate-300 mt-0.5 shrink-0" />
                      <span className="text-xs text-slate-500">{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            </FadeIn>

            {/* Mission 2 */}
            <FadeIn delay={0.1}>
              <div className="bg-white p-8 rounded-lg border border-slate-200 hover:border-slate-300 transition-colors h-full">
                <div className="flex items-center gap-3 mb-5">
                  <div className="w-10 h-10 rounded-md bg-slate-50 border border-slate-100 flex items-center justify-center">
                    <Fingerprint className="w-5 h-5 text-slate-600" />
                  </div>
                  <div>
                    <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Mission 2</div>
                    <h3 className="text-lg font-bold">Payload Integrity Verification</h3>
                  </div>
                </div>
                <p className="text-sm text-slate-500 leading-relaxed mb-5">
                  When Agent A sends a document, image, or dataset to Agent B, how does Agent B
                  know it's genuine? We run every payload through independent forensic analysis —
                  structural validation, consistency checks, image forensics, and adversarial
                  challenge — then produce a tamper-proof verdict.
                </p>
                <div className="space-y-2">
                  {[
                    'Structural validation and injection detection at the gate',
                    'Forensic image analysis (ELA, noise patterns, AI generation detection)',
                    'Cross-field consistency and arithmetic verification',
                    'Adversarial challenge — a process that actively tries to disprove results',
                    'Merkle-chain proof ledger — every verdict chains to the previous one',
                  ].map((item) => (
                    <div key={item} className="flex items-start gap-2">
                      <CheckCircle className="w-3.5 h-3.5 text-slate-300 mt-0.5 shrink-0" />
                      <span className="text-xs text-slate-500">{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            </FadeIn>
          </div>

          <FadeIn delay={0.2} className="mt-6">
            <div className="flex items-center justify-center gap-4">
              <Source href="https://www.nist.gov/caisi/ai-agent-standards-initiative" label="NIST Agent Standards Initiative" />
              <Source href="https://stablecoininsider.org/know-your-agent-kya-in-2026/" label="Know Your Agent (KYA) Framework" />
              <Source href="https://cloudsecurityalliance.org/blog/2026/02/02/the-agentic-trust-framework-zero-trust-governance-for-ai-agents" label="CSA Agentic Trust Framework" />
            </div>
          </FadeIn>
        </div>
      </section>

      {/* ═══════ WHY INDEPENDENT ═══════ */}
      <section id="why" className="py-20 md:py-28 px-6 bg-slate-50 border-y border-slate-100">
        <div className="max-w-5xl mx-auto">
          <FadeIn className="text-center mb-14">
            <p className="text-[12px] font-semibold text-slate-400 uppercase tracking-widest mb-3">Why Independent</p>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-5">
              Trust works best when it's earned independently.<br />
              <span className="text-slate-400">That's why we exist outside the platforms.</span>
            </h2>
          </FadeIn>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {[
              {
                icon: Lock,
                title: 'Immutable proof, not promises',
                desc: 'Every verification verdict is recorded on a Merkle-chain ledger where each record\'s hash chains to the previous one. Any tampering breaks all subsequent records. Verdicts are forged as immutable evidence onto multiple blockchains — public infrastructure that no single entity controls.',
              },
              {
                icon: Eye,
                title: 'Neutral by design, not by promise',
                desc: 'We don\'t build agents or sell agent platforms. That\'s intentional — it means we have no reason to favor one ecosystem over another. The goal is a verification layer governed by protocol rules and cryptographic proof, not commercial relationships.',
              },
              {
                icon: Globe,
                title: 'Cross-platform by design',
                desc: 'Built on the A2A protocol (now under Linux Foundation governance), we verify agents regardless of which ecosystem they came from. An agent from one platform gets the same independent assessment as any other.',
              },
              {
                icon: GitBranch,
                title: 'Verifiable by anyone, controlled by no one',
                desc: 'Smart contracts deployed across multiple blockchains. Any agent, developer, or auditor can query them to verify a trust passport or data proof — for free, without our permission, without an API key. Once a verdict is on-chain, even we can\'t change it. That\'s the point.',
              },
            ].map((item, i) => (
              <FadeIn key={item.title} delay={i * 0.08}>
                <div className="bg-white p-7 rounded-lg border border-slate-200 hover:border-slate-300 transition-colors h-full">
                  <item.icon className="w-6 h-6 text-slate-400 mb-4" />
                  <h3 className="text-base font-bold mb-2 text-slate-900">{item.title}</h3>
                  <p className="text-sm text-slate-500 leading-relaxed">{item.desc}</p>
                </div>
              </FadeIn>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════ SANDBOX ═══════ */}
      <section className="py-20 md:py-28 px-6">
        <div className="max-w-5xl mx-auto">
          <FadeIn className="text-center mb-14">
            <p className="text-[12px] font-semibold text-slate-400 uppercase tracking-widest mb-3">Test Your Agents</p>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-5">
              Not a whitepaper. A sandbox you can run today.
            </h2>
            <p className="text-base text-slate-500 max-w-2xl mx-auto leading-relaxed">
              Bring your agents. Put them through the pipeline. See exactly how they score across
              identity verification, behavioral analysis, payload integrity, and anti-Sybil detection —
              before they go live in production.
            </p>
          </FadeIn>

          <FadeIn>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
              {[
                {
                  step: '01',
                  title: 'Apply for sandbox access',
                  desc: 'Register your organization and describe your agent ecosystem. We provision an isolated environment for your agents to operate in.',
                },
                {
                  step: '02',
                  title: 'Integrate via our SDK',
                  desc: 'Drop in our SDK to connect your agents to the verification pipeline. Standard A2A protocol — if your agent speaks JSON-RPC, it already works.',
                },
                {
                  step: '03',
                  title: 'Get real trust verdicts',
                  desc: 'Your agents earn trust scores through real verification — cryptographic challenges, behavioral analysis, payload forensics. Every result is recorded on an immutable ledger.',
                },
              ].map((item, i) => (
                <motion.div
                  key={item.step}
                  className="bg-white p-7 rounded-lg border border-slate-200 hover:border-slate-300 transition-colors"
                  initial={{ opacity: 0, y: 16 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.1 }}
                  viewport={{ once: true }}
                >
                  <div className="text-3xl font-bold text-slate-100 mb-3 font-mono">{item.step}</div>
                  <div className="text-sm font-bold text-slate-900 mb-2">{item.title}</div>
                  <div className="text-xs text-slate-500 leading-relaxed">{item.desc}</div>
                </motion.div>
              ))}
            </div>
          </FadeIn>

          <FadeIn delay={0.2} className="mt-6 flex justify-center">
            <div className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-50 rounded-md border border-slate-100">
              {['Apply', 'Integrate', 'Test', 'Verify', 'Deploy'].map((step, i) => (
                <React.Fragment key={step}>
                  <span className="text-[10px] font-semibold text-slate-500 tracking-wide">{step}</span>
                  {i < 4 && <ArrowRight className="w-3 h-3 text-slate-300" />}
                </React.Fragment>
              ))}
            </div>
          </FadeIn>

          <FadeIn delay={0.3} className="mt-8 text-center">
            <button
              onClick={() => navigate('/dashboard')}
              className="group px-6 py-2.5 bg-slate-900 hover:bg-slate-800 text-white rounded-md font-semibold text-[12px] tracking-wide transition-all inline-flex items-center gap-2"
            >
              Explore The Command Center <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </FadeIn>
        </div>
      </section>

      {/* ═══════ TECHNOLOGY ═══════ */}
      <section id="technology" className="py-20 md:py-28 px-6 bg-slate-50 border-y border-slate-100">
        <div className="max-w-5xl mx-auto">
          <FadeIn className="text-center mb-14">
            <p className="text-[12px] font-semibold text-slate-400 uppercase tracking-widest mb-3">Infrastructure</p>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-5">
              Open protocols. Immutable proofs. Auditable code.
            </h2>
          </FadeIn>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: 'Agent Protocol', detail: 'A2A Standard', sub: 'Linux Foundation governed', icon: Bot },
              { label: 'Proof Ledger', detail: 'Merkle Chain', sub: 'Append-only, tamper-evident', icon: Layers },
              { label: 'Blockchain', detail: 'Multi-Chain', sub: 'Immutable evidence across chains', icon: Hexagon },
              { label: 'Signing', detail: 'Ed25519 + SHA-256', sub: 'Non-repudiation proofs', icon: Lock },
              { label: 'Forensics', detail: '10 Analyzers', sub: 'ELA, DCT, copy-move, AI detection', icon: Fingerprint },
              { label: 'Storage', detail: 'PostgreSQL', sub: 'Full audit trail', icon: Database },
              { label: 'File Support', detail: '8 Formats', sub: 'PDF, images, Excel, Word, CSV', icon: FileText },
              { label: 'Consensus', detail: 'Dual-Agent', sub: 'Two agents must agree', icon: GitBranch },
            ].map((tech, i) => (
              <FadeIn key={tech.label} delay={i * 0.04}>
                <div className="bg-white p-4 rounded-lg border border-slate-200 text-center hover:border-slate-300 transition-colors">
                  <tech.icon className="w-5 h-5 text-slate-400 mx-auto mb-2" />
                  <div className="text-[11px] text-slate-400 font-medium">{tech.label}</div>
                  <div className="text-sm font-bold text-slate-900 mt-0.5">{tech.detail}</div>
                  <div className="text-[10px] text-slate-400 mt-0.5">{tech.sub}</div>
                </div>
              </FadeIn>
            ))}
          </div>

        </div>
      </section>

      {/* ═══════ MARKET CONTEXT ═══════ */}
      <section className="py-20 md:py-28 px-6">
        <div className="max-w-4xl mx-auto">
          <FadeIn className="text-center mb-14">
            <p className="text-[12px] font-semibold text-slate-400 uppercase tracking-widest mb-3">Market Context</p>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-5">
              The infrastructure is being built now.<br />
              <span className="text-slate-400">The trust layer isn't.</span>
            </h2>
          </FadeIn>

          <FadeIn>
            <div className="space-y-4">
              {[
                {
                  date: 'April 2025',
                  event: 'A2A protocol launches with 50+ technology partners for agent interoperability',
                  source: { label: 'A2A Protocol', href: 'https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/' },
                },
                {
                  date: 'June 2025',
                  event: 'Linux Foundation takes over A2A governance for vendor neutrality',
                  source: { label: 'Linux Foundation', href: 'https://www.linuxfoundation.org/press/linux-foundation-launches-the-agent2agent-protocol-project-to-enable-secure-intelligent-communication-between-ai-agents' },
                },
                {
                  date: 'October 2025',
                  event: 'Major platforms adopt A2A protocol in their agent frameworks',
                  source: { label: 'Linux Foundation A2A', href: 'https://www.linuxfoundation.org/press/linux-foundation-launches-the-agent2agent-protocol-project-to-enable-secure-intelligent-communication-between-ai-agents' },
                },
                {
                  date: 'February 2026',
                  event: 'NIST launches AI Agent Standards Initiative — identity, security, and interoperability',
                  source: { label: 'NIST', href: 'https://www.nist.gov/caisi/ai-agent-standards-initiative' },
                },
                {
                  date: 'February 2026',
                  event: 'Cloud Security Alliance publishes Agentic Trust Framework — zero trust for AI agents',
                  source: { label: 'CSA', href: 'https://cloudsecurityalliance.org/blog/2026/02/02/the-agentic-trust-framework-zero-trust-governance-for-ai-agents' },
                },
                {
                  date: '2026 forecast',
                  event: 'Agentic AI spending hits $201.9B (141% growth). 40% of enterprise apps include agents.',
                  source: { label: 'Gartner via OneReach', href: 'https://onereach.ai/blog/agentic-ai-adoption-rates-roi-market-trends/' },
                },
              ].map((item, i) => (
                <div key={i} className="flex items-start gap-4 p-4 rounded-lg bg-slate-50 border border-slate-100">
                  <div className="text-[11px] font-bold text-slate-400 font-mono w-28 shrink-0 pt-0.5">{item.date}</div>
                  <div className="flex-1">
                    <div className="text-sm text-slate-700 font-medium">{item.event}</div>
                    <div className="mt-1">
                      <Source href={item.source.href} label={item.source.label} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </FadeIn>
        </div>
      </section>

      {/* ═══════ VISION ═══════ */}
      <section className="py-20 md:py-28 px-6 bg-white border-t border-slate-100">
        <div className="max-w-3xl mx-auto">
          <FadeIn className="text-center mb-10">
            <p className="text-[12px] font-semibold text-slate-400 uppercase tracking-widest mb-3">Our Position</p>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-5">
              We're early. Deliberately.
            </h2>
          </FadeIn>
          <FadeIn>
            <div className="prose prose-slate max-w-none text-sm text-slate-500 leading-relaxed space-y-4">
              <p>
                The autonomous agent economy doesn't fully exist yet. In 2025, the
                A2A protocol launched. In 2026, NIST began standardizing agent security. The Cloud Security
                Alliance published its Agentic Trust Framework. The infrastructure is being laid <em>right now</em>.
              </p>
              <p>
                We're not claiming to have all the answers. We are building
                toward something we believe will matter — an open sandbox where companies can test
                their agents, a verification methodology grounded in cryptography rather than trust,
                and immutable records that anyone can audit.
              </p>
              <p>
                Our belief is simple: as autonomous agents begin transacting across different
                ecosystems, there will be a need for an independent place where trust can be
                verified — not by the platforms that built those agents, but by neutral infrastructure
                that treats every agent the same regardless of where it came from.
              </p>
              <p className="text-slate-700 font-medium">
                The technology is built. The sandbox is open. The verification pipeline is running.
                We don't know exactly what shape the future takes —
                but we want to be ready to help when it arrives.
              </p>
            </div>
          </FadeIn>
        </div>
      </section>

      {/* ═══════ CTA ═══════ */}
      <section className="py-20 md:py-28 px-6 bg-slate-50 border-t border-slate-100">
        <div className="max-w-3xl mx-auto text-center">
          <FadeIn>
            <img src="/TheRegistryBase.png" alt="" className="w-28 h-28 mx-auto mb-8 object-contain" />
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-5 text-slate-900">
              The truth should have a home that nobody owns.<br />
              <span className="text-slate-400">That's what we're trying to build.</span>
            </h2>
            <p className="text-base text-slate-500 max-w-xl mx-auto mb-8 leading-relaxed">
              A neutral verification layer for autonomous agents — independent,
              governed by immutable evidence forged across multiple blockchains,
              and open for anyone to query. We're not there yet. But we're building it.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <button
                onClick={() => navigate('/dashboard')}
                className="group px-8 py-3.5 bg-slate-900 hover:bg-slate-800 text-white rounded-md font-semibold text-[13px] tracking-wide transition-all inline-flex items-center gap-2"
              >
                Enter Command Center
                <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
              </button>
            </div>
          </FadeIn>
        </div>
      </section>

      {/* ═══════ FOOTER ═══════ */}
      <footer className="border-t border-slate-100 py-8 px-6">
        <div className="max-w-5xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <img src="/TheRegistryBase.png" alt="" className="w-8 h-8 object-contain" />
            <span className="text-xs font-semibold text-slate-400">The Last Bastion</span>
          </div>
          <div className="flex items-center gap-6 text-[11px] text-slate-400">
            <span>Multi-Chain Proofs</span>
            <span>A2A Protocol</span>
            <span>Global Infrastructure</span>
          </div>
          <div className="text-[11px] text-slate-300">
            {new Date().getFullYear()} The Last Bastion
          </div>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;
