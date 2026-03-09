import React, { useState, useEffect, useRef } from 'react';
import { swarmService } from '../../services/api';
import { Send, Sparkles, Loader2, ArrowRight, Command } from 'lucide-react';

const ChatInterface = ({ onSwarmTriggered }) => {
    const [messages, setMessages] = useState([]);
    const [inputValue, setInputValue] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const scrollRef = useRef(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [messages]);

    const handleSend = async () => {
        if (!inputValue.trim()) return;

        const userText = inputValue;
        setMessages(prev => [...prev, { role: 'user', text: userText }]);
        setInputValue('');
        setIsTyping(true);

        try {
            const response = await swarmService.chat(userText);
            const data = response.data;
            setMessages(prev => [...prev, { role: 'assistant', text: data.response }]);

            if (data.intent === 'GATHER_DATA' && data.mission) {
                onSwarmTriggered?.(data.mission.region, data.mission.category);
            }
        } catch (err) {
            setMessages(prev => [...prev, { role: 'assistant', text: "Service unavailable." }]);
        } finally {
            setIsTyping(false);
        }
    };

    return (
        <div className="w-full max-w-3xl mx-auto flex flex-col items-center py-10 animate-slide-up">
            <h1 className="text-4xl font-bold text-text-primary tracking-tight mb-12 text-center">
                What would you like to achieve?
            </h1>

            {/* Central Focused Input (Clean Frost) */}
            <div className="w-full relative">
                <div className="relative bg-white border border-border rounded-2xl shadow-sm flex flex-col min-h-[140px]">
                    <div className="flex items-center gap-3 px-6 py-3 border-b border-slate-50 bg-slate-50/50">
                        <Command size={14} className="text-text-secondary" />
                        <span className="text-[10px] font-bold uppercase tracking-widest text-text-secondary">Intelligence Link</span>
                    </div>

                    <div className="flex-1 flex px-6">
                        <textarea
                            value={inputValue}
                            onChange={(e) => setInputValue(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && (e.preventDefault(), handleSend())}
                            placeholder="Describe your goal..."
                            className="w-full bg-transparent py-6 text-xl text-text-primary focus:outline-none placeholder:text-slate-300 resize-none font-medium"
                            rows={1}
                        />
                    </div>

                    <div className="flex items-center justify-between px-6 py-4 border-t border-slate-50">
                        <div className="flex items-center gap-4 text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                            <span className="bg-slate-100 px-2 py-1 rounded">Beta</span>
                        </div>
                        <button
                            onClick={handleSend}
                            className={`p-2.5 rounded-lg transition-all ${inputValue.trim() ? 'bg-primary text-white shadow-md' : 'bg-slate-100 text-slate-300'}`}
                        >
                            <ArrowRight size={20} strokeWidth={3} />
                        </button>
                    </div>
                </div>
            </div>

            {/* Message History (Minimal) */}
            {messages.length > 0 && (
                <div className="w-full mt-10 space-y-6">
                    {messages.slice(-2).map((msg, i) => (
                        <div key={i} className={`flex items-start gap-4 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                            <div className={`px-5 py-3 rounded-xl text-sm font-medium leading-relaxed max-w-[85%] ${msg.role === 'user'
                                ? 'bg-slate-900 text-white shadow-sm'
                                : 'bg-white border border-border text-text-primary shadow-xs'
                                }`}>
                                {msg.text}
                            </div>
                        </div>
                    ))}
                    {isTyping && (
                        <div className="flex items-center gap-3">
                            <Loader2 size={12} className="animate-spin text-primary" />
                            <span className="text-[10px] font-bold text-primary uppercase tracking-widest opacity-60">Working...</span>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default ChatInterface;
