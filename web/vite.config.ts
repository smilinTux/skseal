import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import { resolve } from "path";

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: "node",
    globals: true,
    include: ["tests/**/*.{test,spec}.{ts,js}"],
    testTimeout: 30000,
  },
  build: {
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      name: "SKSealWeb",
      formats: ["es", "cjs"],
      fileName: (format) => `index.${format === "es" ? "js" : "cjs"}`,
    },
    rollupOptions: {
      // Treat peer deps as external — consumers provide their own Vue/OpenPGP.
      external: ["vue", "openpgp"],
      output: {
        globals: {
          vue: "Vue",
          openpgp: "OpenPGP",
        },
      },
    },
    sourcemap: true,
  },
});
