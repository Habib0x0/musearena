# MuseArena UI Standard

**Status: Final** — accepted by the project owner in session, 2026-11-03
(grill interview, Q1–Q9). Implementation requires a separate go.

## Scope

Settled 2026-11-03 (grill Q1): the standard covers the **whole authenticated
product app** in `frontend/` — shell, spacing/width rules, and every page:

- Overview (`/`), Designer (`/designer`), Environments (`/environments`,
  `/environments/:id`), Exercises (`/runs`), Red Team (`/red`), Blue Team
  (`/blue`), Monitoring (`/monitoring`), Personas (`/personas`), Templates
  (`/templates`), Traces & Datasets (`/traces`), Learning (`/learning`),
  Settings (`/settings`), Login (`/login`).

The separate `marketing/` site is **in scope** (Q9): same tokens, both
themes. It rolls out after the app pages (Q8 order).

## Settled decisions

1. **Scope = whole-app UI standard**, not Designer-only. (Q1)
2. **Both themes, with a user toggle.** (Q2) Implementation consequences
   accepted with this choice: fixed hex tokens in `tailwind.config.js`
   refactor to CSS variables; every page is QA'd in both themes; the toggle
   persists per user.
3. **Default theme follows the OS** (`prefers-color-scheme`); an explicit
   toggle choice is remembered and wins over the OS thereafter. (Q3)
4. **Full-bleed shell everywhere; no page-level max-width.** Tables, grids,
   topology, and the Designer canvas use the whole window. Line-length caps
   live inside prose blocks only. (Q4)
5. **One CSS-variable token layer; keep existing primitives; shadcn-style
   for new components.** (Q5) Tailwind colors read variables, so components
   carry no per-theme (`dark:`) color classes. `ops-*` classes survive but
   consume the same variables. No shadcn-CLI big-bang migration.
6. **One density.** (Q6) The current comfortable density is the standard;
   compactness is a property of data-dense components (tables, mono
   metadata), not a user toggle. No density setting.
7. **Functional motion only.** (Q7) Animation explains state changes
   (open/close/slide, streaming, view switches), ~500ms cap. No decorative
   or ambient motion; data visualizations are static; `prefers-reduced-motion`
   always wins.
8. **Rollout: foundation first, then page-by-page.** (Q8) Token layer +
   toggle + shell land as one foundation; per-page dual-theme verification
   follows in usage order — Designer, Environments, Exercises, then the rest.
9. **Marketing site in scope.** (Q9) Same token layer and both themes on
   `marketing/`; it follows the app pages in rollout order.

## Current state (facts, 2026-11-03)

- Shell: fixed left sidebar (276px / 76px collapsed), sticky top header,
  full-bleed content (no max-width cap) with padding `px-4 → 2xl:px-10`.
- Theme: light. Zinc neutrals (`ink #fafafa`, `panel #ffffff`, `line #e4e4e7`,
  `paper #09090b`), accents `mint #10b981`, `gold #f59e0b`, `danger #dc2626`,
  `cyber #3b82f6`. Fonts: Geist/Inter sans + display, Geist Mono.
- Components: ad-hoc `ops-*` classes in `src/index.css`, shared primitives in
  `src/components/ui.tsx`, shadcn-style drop-ins under `src/components/ui/`.
- Motion: designer artifact slide + width transition (500ms), fade-up tab
  content; `prefers-reduced-motion` disables movement. Topology is a static
  SVG graph (no Three.js/canvas animation).

## Open questions

- [x] Q2 Theme: **both, with toggle**.
- [x] Q3 Default theme: **follow OS**, remember explicit toggle.
- [x] Q4 Width rule: **full-bleed everywhere**, prose caps itself.
- [x] Q5 Component system: **token layer + existing primitives**, shadcn for new.
- [x] Q6 Density: **one density**, compact inside data components only.
- [x] Q7 Motion: **functional only**, static data viz, reduced-motion wins.
- [x] Q8 Rollout: **foundation first, page-by-page**, Designer first.
- [x] Q9 Marketing: **in scope**, after app pages.
- [x] Done means: checklist below, accepted 2026-11-03.

## Scope contract (Final — accepted 2026-11-03)

**Boundary.** In scope: `frontend/` (shell + all routes above) and
`marketing/` visual layer — tokens, themes, layout width, density, motion.
Out of scope: backend code, data/API contracts, DB migrations, feature work,
density toggle, shadcn-CLI migration, decorative motion.

**Done means** (future implementation is finished only when all hold):

1. CSS-variable token layer defines both palettes; Tailwind colors read
   variables in `frontend/` and `marketing/`; no per-theme color classes
   remain in components.
2. Theme toggle in the shell; first load follows the OS; explicit choice
   persists across reloads.
3. Every app route and marketing page verified in **both** themes
   (screenshot or live check) with typecheck, lint, and build green.
4. Full-bleed confirmed on a wide viewport; no page-level max-width.
5. Motion audit: only functional animation remains; reduced-motion disables
   movement; topology stays a static graph.

**Staging.** Foundation → Designer → Environments → Exercises → remaining
app pages → marketing. Each stage is separately verifiable; accepting this
contract does not auto-approve later-stage palette details, which are
reviewed when the Designer dark pass lands.

**Risks.** Hidden hardcoded light colors (badges, alerts, topology SVG,
table hovers) surface per page; dual-theme QA doubles visual checking;
marketing build is separate, so token sharing must not create a cross-package
import that violates the repo modularity rule (duplicate the variable sheet
or share via `shared/` conventions — implementation choice).

**Unresolved.** Exact dark palette values (settled by review at Designer
stage). Live DB migrations 0005–0010 remain blocked outside this contract.
