/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
      colors: {
        darkBase: '#0f172a',
        darkCard: '#1e293b',
        darkAccent: '#38bdf8',
        darkPrimary: '#0ea5e9'
      }
    },
  },
  plugins: [],
}
