import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
    LayoutDashboard,
    Truck,
    Network,
    Inbox,
    ShieldCheck,
    Cpu,
    Shield,
    Eye,
    FileKey
} from 'lucide-react';
import { DEMO_MODE } from '../../services/api';

const navGroups = [
    {
        label: 'Supply Chain',
        items: [
            { id: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
            { id: '/dashboard/agents', label: 'Agent Network', icon: Network },
            { id: '/dashboard/supply-chain', label: 'Supply Chain Flow', icon: Truck },
        ],
    },
    {
        label: 'Verification',
        items: [
            { id: '/dashboard/submissions', label: 'Submissions', icon: Inbox },
            { id: '/dashboard/verification', label: 'Verification', icon: ShieldCheck },
            { id: '/dashboard/bastion', label: 'Bastion Protocol', icon: Shield },
            { id: '/dashboard/passport', label: 'Passport Check', icon: FileKey },
        ],
    },
    {
        label: 'Blockchain',
        items: [
            { id: '/dashboard/blockchain', label: 'On-Chain Registry', icon: Cpu },
        ],
    },
];

const SidebarNav = ({ stats }) => {
    const location = useLocation();
    const activePath = location.pathname;

    return (
        <aside className="w-64 h-screen bg-white flex flex-col border-r border-slate-200 fixed left-0 top-0 z-50">
            {/* Branding */}
            <div className="p-8 border-b border-slate-100">
                <div className="flex items-center gap-3 mb-2">
                    <img src="/TheRegistryBase.png" alt="The Last Bastion" className="w-16 h-16 object-contain" />
                    <div>
                        <span className="font-bold text-xl tracking-tighter text-slate-900 block leading-tight">The Last Bastion</span>
                        <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block">Command Center</span>
                    </div>
                </div>
            </div>

            {/* Navigation Groups */}
            <div className="px-4 pt-6 pb-4 flex-1 overflow-y-auto thin-scrollbar">
                {navGroups.map((group) => (
                    <div key={group.label} className="mb-5">
                        <div className="text-[10px] uppercase tracking-widest font-bold text-slate-400 px-4 mb-2">
                            {group.label}
                        </div>
                        <nav className="space-y-0.5">
                            {group.items.map((item) => {
                                const isActive = activePath === item.id;
                                return (
                                    <Link
                                        key={item.id}
                                        to={item.id}
                                        className={`w-full flex items-center gap-3 px-4 py-2.5 text-[11px] font-bold uppercase tracking-wider transition-colors rounded-sm ${isActive
                                                ? 'bg-slate-100 text-slate-900 border-l-[3px] border-slate-900'
                                                : 'text-slate-500 hover:text-slate-900 hover:bg-slate-50 border-l-[3px] border-transparent'
                                            }`}
                                    >
                                        <item.icon size={15} strokeWidth={2.5} className={isActive ? 'text-slate-900' : ''} />
                                        <span>{item.label}</span>
                                    </Link>
                                );
                            })}
                        </nav>
                    </div>
                ))}
            </div>

            {/* Bottom */}
            <div className="p-4 border-t border-slate-100 bg-slate-50 space-y-2">
                {DEMO_MODE && (
                    <div className="flex items-center gap-2 px-3 py-2 bg-slate-100 border border-slate-300 rounded-sm">
                        <Eye size={12} className="text-slate-500 shrink-0" />
                        <span className="text-[9px] font-bold text-slate-600 uppercase tracking-widest">Demo Mode — Read Only</span>
                    </div>
                )}
                <div className="flex items-center justify-between px-3 py-2 bg-white border border-slate-200 w-full shadow-sm rounded-sm">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Blockchain</span>
                    <span className="text-[10px] font-bold text-slate-700 uppercase tracking-wider font-mono">Polygon Amoy</span>
                </div>
            </div>
        </aside>
    );
};

export default SidebarNav;
