import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { tauriClient } from "./core/bridge";
import "./styles/theme.css";

// The packaged app talks to the native core over Tauri IPC. In a plain
// browser dev server without Tauri, the app shows the welcome screen and
// reports safe errors instead of a fake client (no synthetic accounts in a
// window that looks real).
const client = tauriClient();

// Theme from the OS by default (System); Light/Dark overrides are
// device-local settings.
const media = window.matchMedia("(prefers-color-scheme: dark)");
const applySystemTheme = () => {
  if (!document.documentElement.dataset.theme) {
    document.documentElement.dataset.theme = media.matches ? "dark" : "light";
  }
};
applySystemTheme();
media.addEventListener("change", applySystemTheme);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App client={client} />
  </StrictMode>,
);
