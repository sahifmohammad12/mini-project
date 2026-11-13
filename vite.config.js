import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Forwards every /api/* request to the backend during dev
      // This eliminates CORS issues and hardcoded localhost URLs
      "/api": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
    },
  },
});
