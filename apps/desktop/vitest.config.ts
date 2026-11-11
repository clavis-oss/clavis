import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    include: ["tests/**/*.test.{ts,tsx}", "src/**/*.test.{ts,tsx}"],
  },
  resolve: {
    alias: {
      "@clavis/contracts": resolve(__dirname, "../../packages/contracts/src/index.ts"),
      "@clavis/design-tokens": resolve(__dirname, "../../packages/design-tokens/src/tokens.ts"),
    },
  },
});
