export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        slate: {
          900: "#0f172a",
          800: "#1e293b",
          700: "#334155",
        },
        cyan: {
          400: "#22d3ee",
          500: "#06b6d4",
        }
      },
    },
  },
  darkMode: "class",
  plugins: [],
}
