import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const backendTarget = env.VITE_BACKEND_PROXY_TARGET || "http://127.0.0.1:8000";

  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/health": backendTarget,
        "/upload": backendTarget,
        "/analyze": backendTarget,
        "/result": backendTarget,
        "/sandbox": backendTarget,
      },
    },
  };
});
