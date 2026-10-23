import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Em dev o Vite (5173) repassa /api para a API Python (python -m zap_mcp.web).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": "http://127.0.0.1:8765" },
  },
});
