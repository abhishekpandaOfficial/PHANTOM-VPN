# Landing UI Module

This directory keeps the public VPN landing page self-contained inside the repo.

## Structure

- `styles/tokens.css`: design tokens, utilities, shared base rules
- `styles/shell.css`: navbar, hero, footer, and shell-level layout
- `styles/sections.css`: section cards, pricing, FAQ, comparison, CTA
- `styles/modal.css`: trial modal, onboarding wizard, form states
- `scripts/state.js`: shared client-side state and constants
- `scripts/dom.js`: DOM lookup and small DOM helpers
- `scripts/api.js`: public API client for the landing page
- `scripts/ui.js`: presentation logic for theme, modal, wizard, QR, FAQ
- `scripts/app.js`: bootstrap and event wiring

## Runtime contract

- `pages/landing.html` is the shell entry point
- `/brand/*` serves repo-owned images and icons
- `/ui/*` serves these landing modules from both Vercel and the Node backend
- trial creation and connection verification still use the existing public API routes
