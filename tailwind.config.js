/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        bg: "var(--bg)",
        ink: "var(--ink)",
        mute: "var(--mute)",
        rule: "var(--rule)",
      },
      fontFamily: {
        sans: ['"Inter Tight"', '"Helvetica Neue"', "Arial", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "Menlo", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
