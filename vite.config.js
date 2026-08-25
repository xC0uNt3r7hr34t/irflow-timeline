/**
 * vite.config.js — Windows build
 *
 * Key Windows changes:
 *  - base: "./"  — critical for Electron on Windows.
 *    Without this, the built index.html references assets as absolute paths
 *    (/assets/...) which fail when Electron loads the file via file:// protocol
 *    on Windows (absolute paths resolve to C:\ not the app directory).
 *  - outDir: "dist" — standard; electron/main.js loads dist/index.html.
 *  - assetsDir: "assets" — keeps asset paths predictable.
 *  - sourcemap: false in production (speeds up build, no change needed for dev).
 */

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Inject a strict Content-Security-Policy ONLY into the production build's index.html
// (the file:// page in the packaged app). Dev (vite serve) is left untouched so HMR
// keeps working. The renderer makes no fetch/eval and loads only its own same-origin
// bundle; 'unsafe-inline' style is required for the inline <style> in index.html, and
// frame-src 'self' permits the Sigma HTML-report srcDoc iframe.
const cspMetaPlugin = {
  name: "irflow-csp-meta",
  apply: "build",
  transformIndexHtml() {
    return [{
      tag: "meta",
      injectTo: "head-prepend",
      attrs: {
        "http-equiv": "Content-Security-Policy",
        content: [
          "default-src 'self'",
          "script-src 'self'",
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data: blob:",
          "font-src 'self' data:",
          "media-src 'self' data: blob:",
          "connect-src 'self'",
          "frame-src 'self'",
          "object-src 'none'",
          "base-uri 'self'",
          "form-action 'self'",
        ].join("; "),
      },
    }];
  },
};

export default defineConfig({
  plugins: [react(), cspMetaPlugin],
  base: "./",

  build: {
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: false,
    // Raise chunk size warning threshold — the monolithic App.jsx is intentionally large.
    chunkSizeWarningLimit: 8000,
    rollupOptions: {
      output: {
        // Single-chunk output avoids dynamic import path issues under file:// on Windows.
        manualChunks: undefined,
      },
    },
  },

  server: {
    // Dev server port — must match the URL in main.js createWindow (http://localhost:5173)
    port: 5173,
    strictPort: true,
  },

  // Ensure Vite doesn't try to resolve Node built-ins that are only available in main process
  resolve: {
    alias: {},
  },
});
