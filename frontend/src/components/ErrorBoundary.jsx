import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }

    componentDidCatch(error, info) {
        console.error('ErrorBoundary caught:', error, info?.componentStack);
    }

    render() {
        if (this.state.hasError) {
            return (
                <div className="flex flex-col items-center justify-center p-12 text-center">
                    <div className="w-12 h-12 bg-slate-100 rounded-sm flex items-center justify-center border border-slate-300 mb-4">
                        <AlertTriangle size={24} className="text-slate-600" />
                    </div>
                    <h3 className="text-sm font-extrabold text-slate-900 uppercase tracking-widest mb-2">Render Error</h3>
                    <p className="text-[10px] font-mono text-slate-500 max-w-md mb-4">
                        {this.state.error?.message || 'An unexpected error occurred while rendering this view.'}
                    </p>
                    <button
                        onClick={() => this.setState({ hasError: false, error: null })}
                        className="flex items-center gap-2 px-4 py-2 bg-slate-900 text-white text-[10px] font-bold uppercase tracking-widest rounded-sm hover:bg-slate-700 transition-colors"
                    >
                        <RefreshCw size={12} />
                        Retry
                    </button>
                </div>
            );
        }
        return this.props.children;
    }
}

export default ErrorBoundary;
