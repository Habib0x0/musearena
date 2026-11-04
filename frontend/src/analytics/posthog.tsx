import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { useAuth } from "@clerk/clerk-react";
import posthog from "posthog-js";

/**
 * Product analytics (PostHog). Off unless a key is configured: with no
 * VITE_POSTHOG_KEY the app makes no analytics network calls at all. When a
 * session exists, the Clerk user id becomes the analytics distinct id, so
 * events link to the operator behind the action and nothing else about the
 * session (tokens, org data) ever reaches the analytics client.
 */

let bootstrapped = false;
let enabled = false;

function ensurePostHog(): boolean {
  if (bootstrapped) return enabled;
  bootstrapped = true;
  const key = (import.meta as { env?: Record<string, string> }).env?.VITE_POSTHOG_KEY;
  if (!key) return false;
  posthog.init(key, {
    api_host: (import.meta as { env?: Record<string, string> }).env?.VITE_POSTHOG_HOST ?? "https://us.i.posthog.com",
    capture_pageview: false, // PageViews hook below owns pageview timing
    persistence: "localStorage+cookie",
  });
  enabled = true;
  return true;
}

/** Route changes become pageviews, one per navigation. */
export function PostHogPageViews() {
  const { pathname, search } = useLocation();
  useEffect(() => {
    if (!ensurePostHog()) return;
    posthog.capture("$pageview", { $pathname: pathname, $search: search });
  }, [pathname, search]);
  return null;
}

/** Bind the signed-in Clerk user to the analytics identity. */
export function PostHogIdentity() {
  const { isLoaded, isSignedIn, userId } = useAuth();
  useEffect(() => {
    if (!ensurePostHog()) return;
    if (isLoaded && isSignedIn && userId) posthog.identify(userId);
  }, [isLoaded, isSignedIn, userId]);
  return null;
}
