import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RotateCcw, Home } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[SentinelGrid ErrorBoundary] Caught error:', error, errorInfo);
  }

  public handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="p-8 rounded-2xl bg-[#0F172A] border border-red-500/30 text-center max-w-lg mx-auto my-12 shadow-2xl">
          <div className="w-14 h-14 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 mx-auto mb-4">
            <AlertTriangle className="w-7 h-7" />
          </div>
          <h2 className="text-lg font-bold text-white mb-2">
            {this.props.fallbackTitle || 'Component Display Recovered'}
          </h2>
          <p className="text-xs text-slate-400 mb-4 leading-relaxed font-mono">
            {this.state.error?.message || 'An unexpected rendering issue occurred.'}
          </p>
          <div className="flex items-center justify-center gap-3">
            <button
              onClick={this.handleReset}
              className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-semibold flex items-center gap-2 transition-all shadow-md shadow-emerald-500/20 active:scale-95"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Retry View</span>
            </button>
            {this.props.onReset && (
              <button
                onClick={this.props.onReset}
                className="px-4 py-2 rounded-xl bg-[#182335] hover:bg-[#202E44] text-slate-200 border border-[#2D3F59] text-xs font-medium flex items-center gap-2 transition-colors active:scale-95"
              >
                <Home className="w-4 h-4 text-slate-400" />
                <span>Return to Overview</span>
              </button>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
