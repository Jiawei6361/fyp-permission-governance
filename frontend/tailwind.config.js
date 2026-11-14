/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Cascadia Code", "Consolas", "monospace"],
      },
      colors: {
        // Benchmark series (validated categorical slots 1 and 2 from the dataviz palette)
        proposed: "#2a78d6",
        baseline: "#eb6834",
      },
    },
  },
  plugins: [],
};
