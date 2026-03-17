/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          primary: '#0a0e1a',
          secondary: '#0f1629',
          card: '#111827',
          border: '#1e2d4a',
        },
        accent: {
          primary: '#00d4ff',
          secondary: '#7c3aed',
          success: '#10b981',
          warn: '#f59e0b',
          danger: '#ef4444',
        },
        sev: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#f59e0b',
          low: '#3b82f6',
          info: '#6b7280',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
