/**
 * Minimal classnames joiner (shadcn's `cn` contract without clsx/tailwind-merge:
 * this app's class strings never rely on Tailwind conflict resolution).
 */
export type ClassValue = string | number | false | null | undefined;

export function cn(...inputs: ClassValue[]): string {
  return inputs.filter(Boolean).join(" ");
}
