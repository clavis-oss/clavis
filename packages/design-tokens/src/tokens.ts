/**
 * Clavis design tokens — single source of truth shared by the desktop CSS
 * theme and the mobile token mapping (document 02). Values are semantic
 * tokens, not scattered raw values.
 */

export const light = {
  "surface.canvas": "#F4F6F8",
  "surface.panel": "#FFFFFF",
  "surface.sidebar": "#F9FAFB",
  "surface.hover": "#EDF2F6",
  "border.subtle": "#D8E0E8",
  "text.primary": "#152131",
  "text.secondary": "#526377",
  "text.muted": "#62748A",
  "accent.primary": "#08785F",
  "accent.onPrimary": "#FFFFFF",
  "status.success": "#08785F",
  "status.warning": "#805400",
  "status.danger": "#B32636",
  "focus.ring": "#245FC7",
} as const;

export const dark = {
  "surface.canvas": "#10151D",
  "surface.panel": "#161D27",
  "surface.sidebar": "#121923",
  "surface.hover": "#202B39",
  "border.subtle": "#2B3747",
  "text.primary": "#EFF4FA",
  "text.secondary": "#A6B6C9",
  "text.muted": "#8C9EB3",
  "accent.primary": "#62E2BF",
  "accent.onPrimary": "#0D2921",
  "status.success": "#62E2BF",
  "status.warning": "#F4C66B",
  "status.danger": "#FF969A",
  "focus.ring": "#8EBBFF",
} as const;

/** Spacing scale: 4, 8, 12, 16, 24, 32. */
export const spacing = [4, 8, 12, 16, 24, 32] as const;

/** Radii: rows 12, dialogs 16, controls 8. */
export const radius = { row: 12, dialog: 16, control: 8 } as const;

/**
 * Type sizes: screen title 24/30 semibold; section 16/24 semibold;
 * body 14/20; metadata 12/18; OTP 26/32 medium.
 */
export const type = {
  title: { size: 24, lineHeight: 30, weight: 600 },
  section: { size: 16, lineHeight: 24, weight: 600 },
  body: { size: 14, lineHeight: 20, weight: 400 },
  metadata: { size: 12, lineHeight: 18, weight: 400 },
  otp: { size: 26, lineHeight: 32, weight: 500 },
} as const;

/** Desktop controls >= 36 px; mobile targets >= 44 dp/pt. */
export const sizing = {
  desktopControlMin: 36,
  desktopPointerTarget: { width: 36, height: 36 },
  mobileTarget: { width: 44, height: 44 },
  accountRowMin: 88,
  issuerTile: 40,
  toolbar: 64,
  sidebar: 184,
  sidebarBreakpoint: 840,
  twoRowBreakpoint: 640,
  detailMaxWidth: 440,
} as const;

/** Motion: transitions <= 150 ms; respect reduced motion. */
export const motion = {
  transitionMs: 150,
  clipboardClearSeconds: 30,
  inactivityLockMinutes: 5,
  syncDebounceMs: 750,
  syncPollSeconds: 60,
} as const;

export type ThemeName = "system" | "light" | "dark";
export type TokenSet = typeof light | typeof dark;

export function tokensFor(theme: "light" | "dark"): TokenSet {
  return theme === "light" ? light : dark;
}
