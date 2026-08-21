/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        paper: '#F1F0EA',
        panel: '#FBFAF6',
        ink: '#1A1B17',
        inksoft: '#43443D',
        muted: '#75746A',
        rule: '#DBD9CE',
        rulehard: '#B9B7AA',
        signal: '#16794C',
        critical: '#B42318',
        high: '#BC5414',
        medium: '#96700A',
        low: '#16794C',
        info: '#2F5FA8',
      },
      fontFamily: {
        display: ['Archivo', 'system-ui', 'sans-serif'],
        mono: ['IBM Plex Mono', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
}
