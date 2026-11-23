/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: "#0B0F17",
        surface: {
          DEFAULT: "#131A26",
          elevated: "#182232",
          border: "#1F2937",
          hover: "#222E42"
        },
        status: {
          safe: "#10B981",       // Emerald Green ("You're protected")
          safeLight: "#34D399",
          safeDark: "#059669",
          warn: "#F59E0B",       // Soft Amber ("Recommendation")
          warnLight: "#FBBF24",
          danger: "#EF4444",     // Coral Red ("Threat blocked")
          dangerLight: "#F87171",
          info: "#00F0FF",
        }
      },
      fontFamily: {
        sans: ['"Inter"', 'system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      boxShadow: {
        'card': '0 4px 20px -2px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(31, 41, 55, 0.8)',
        'card-hover': '0 8px 30px -4px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(16, 185, 129, 0.3)',
        'safe-glow': '0 0 25px rgba(16, 185, 129, 0.25)',
        'warn-glow': '0 0 25px rgba(245, 158, 11, 0.25)',
        'danger-glow': '0 0 25px rgba(239, 68, 68, 0.25)',
      },
      borderRadius: {
        'card': '16px',
        '2xl': '16px',
      }
    },
  },
  plugins: [],
}
