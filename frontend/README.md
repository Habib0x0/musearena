# frontend/

MuseArena product app (authenticated console): Overview, conversational
Designer (chat + artifact pane), Environments, Exercises, Personas,
Traces & Datasets.

Structure: `pages/` routes, `components/` UI, `lib/` data layer, `hooks/`
— no page logic in components. Imports `@musearena/shared` types only.
Auth: Clerk; live state: Supabase Realtime (wired in T-2/T-3).

Run: `npm run dev -- --port 5173 --host 127.0.0.1` from this directory.
