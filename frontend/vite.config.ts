import { existsSync, unlinkSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

const rootDir = path.dirname(fileURLToPath(import.meta.url));
const PAGES_BASE = "/ens_ad-auditor/dist/";

const PAGES_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "style-src-attr 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "worker-src 'none'",
  "manifest-src 'none'",
].join("; ");

function omitUnusedPublic(): Plugin {
  return {
    name: "omit-unused-public",
    closeBundle() {
      const leftover = path.resolve(rootDir, "../dist/intro.mp4");
      if (existsSync(leftover)) unlinkSync(leftover);
    },
  };
}

function pagesHead(): Plugin {
  return {
    name: "pages-head",
    transformIndexHtml(html) {
      return {
        html,
        tags: [
          {
            tag: "meta",
            attrs: { "http-equiv": "Content-Security-Policy", content: PAGES_CSP },
            injectTo: "head-prepend",
          },
          {
            tag: "meta",
            attrs: { name: "referrer", content: "no-referrer" },
            injectTo: "head-prepend",
          },
        ],
      };
    },
  };
}

// In dev, /api/* is proxied to the FastAPI backend (uvicorn on :8000),
// so the frontend can call relative URLs and avoid CORS issues.
export default defineConfig(({ mode }) => {
  const pages = mode === "pages";
  return {
    plugins: pages ? [react(), pagesHead(), omitUnusedPublic()] : [react()],
    base: pages ? PAGES_BASE : "/",
    build: {
      outDir: pages ? "../dist" : "dist",
      emptyOutDir: true,
      modulePreload: false,
    },
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: process.env.VITE_BACKEND_URL ?? "http://127.0.0.1:8000",
          changeOrigin: true,
        },
      },
    },
    preview: {
      port: 4173,
      proxy: {
        "/api": {
          target: process.env.VITE_BACKEND_URL ?? "http://127.0.0.1:8000",
          changeOrigin: true,
        },
      },
    },
  };
});
