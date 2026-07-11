import { Component, type ErrorInfo, type ReactNode } from 'react';

type Props = { children: ReactNode };
type State = { error: Error | null };

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[TinyKnights] Uncaught error:', error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="min-h-dvh flex flex-col items-center justify-center gap-6 px-6 text-center bg-parchment">
          <div className="text-6xl" aria-hidden="true">🛡️</div>
          <h1 className="font-display text-2xl font-extrabold text-knight-blue-dark">
            Oops — something went sideways!
          </h1>
          <p className="text-gray-600 font-bold max-w-sm">
            Your progress is safe. Tap below to reload and get back to questing.
          </p>
          <button
            onClick={() => window.location.reload()}
            className="rounded-2xl bg-knight-blue text-white font-display font-extrabold text-lg px-8 py-3 shadow-md hover:bg-knight-blue-dark transition-colors"
          >
            Reload Game
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
