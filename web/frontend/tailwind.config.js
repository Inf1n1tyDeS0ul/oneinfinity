/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          primary:  '#07090f',
          secondary:'#0c101b',
          card:     '#0f1523',
          elevated: '#131c2e',
          border:   '#1c2a42',
          muted:    '#1a2540',
        },
        accent: {
          primary:  '#00d9ff',
          secondary:'#6366f1',
          success:  '#10b981',
          warn:     '#f59e0b',
          danger:   '#ef4444',
          purple:   '#a855f7',
          orange:   '#f97316',
          pink:     '#ec4899',
          lime:     '#84cc16',
        },
        sev: {
          critical: '#ef4444',
          high:     '#f97316',
          medium:   '#f59e0b',
          low:      '#3b82f6',
          info:     '#6b7280',
        },
        neon: {
          cyan:   '#00d9ff',
          green:  '#00ff87',
          purple: '#b400ff',
          red:    '#ff0040',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
      },
      fontSize: {
        '2xs': ['10px', { lineHeight: '14px' }],
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic':  'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'cyber-grid':      'linear-gradient(rgba(0,217,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,217,255,0.03) 1px, transparent 1px)',
      },
      backgroundSize: {
        'grid-40': '40px 40px',
      },
      boxShadow: {
        'glow-cyan':   '0 0 20px rgba(0, 217, 255, 0.15), 0 0 40px rgba(0, 217, 255, 0.05)',
        'glow-red':    '0 0 20px rgba(239, 68, 68, 0.15)',
        'glow-green':  '0 0 20px rgba(16, 185, 129, 0.15)',
        'glow-purple': '0 0 20px rgba(99, 102, 241, 0.15)',
        'glow-orange': '0 0 20px rgba(249, 115, 22, 0.15)',
        'card':        '0 1px 3px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.03)',
        'card-hover':  '0 4px 12px rgba(0,0,0,0.6), 0 0 0 1px rgba(0,217,255,0.1)',
        'modal':       '0 25px 50px rgba(0,0,0,0.8), 0 0 80px rgba(0,217,255,0.05)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line':  'scan-line 2s linear infinite',
        'flicker':    'flicker 4s linear infinite',
        'fade-in':    'fade-in 0.2s ease-out',
        'slide-in':   'slide-in 0.2s ease-out',
      },
      keyframes: {
        'scan-line': {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'flicker': {
          '0%, 19%, 21%, 23%, 25%, 54%, 56%, 100%': { opacity: '1' },
          '20%, 24%, 55%': { opacity: '0.6' },
        },
        'fade-in': {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
        'slide-in': {
          from: { opacity: '0', transform: 'translateY(-8px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
      },
      transitionDuration: {
        '150': '150ms',
        '200': '200ms',
        '300': '300ms',
      },
    },
  },
  plugins: [],
}
