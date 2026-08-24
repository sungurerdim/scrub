// The window's only way of asking for anything.
//
// Every call here is a command on the Rust side, and every type mirrors what
// that side sends. Nothing in the interface computes a total, decides what a
// duplicate is, or works out whether something is safe to move: those answers
// come from the pipeline, and asking twice in two languages is how two answers
// start to differ.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export type Stage = "scan" | "analyze" | "plan" | "preflight" | "apply";

export interface Root {
  provider: string;
  account: string | null;
  path: string;
  origin: string;
}

export interface Link {
  link: string;
  target: string;
}

export interface Providers {
  roots: Root[];
  notBackedUp: Link[];
  unsettled: Link[];
  providerOwned: number;
}

export interface Beginning {
  home: string;
  workspace: string;
  providers: Providers;
  ready: Stage[];
}

export interface Unread {
  path: string;
  reason: string;
}

export interface Inventory {
  entries: number;
  files: number;
  directories: number;
  links: number;
  bytes: number;
  inCloud: number;
  unread: Unread[];
}

export interface Findings {
  proven: number;
  redundant: number;
  reclaimable: number;
  unchecked: number;
  toSettle: number;
}

export interface GroupRow {
  index: number;
  name: string;
  copies: number;
  size: number;
  reclaimable: number;
  proven: boolean;
}

export interface Copy {
  path: string;
  modified: number | null;
  created: number | null;
  local: boolean;
  sameFile: boolean;
}

export interface StepVerdict {
  grade: "pass" | "hold" | "fail";
  impediment: string | null;
}

export interface Step {
  index: number;
  kind: "createDirectory" | "move" | "quarantine";
  subject: string;
  destination: string | null;
  frees: number;
  because: string;
  verdict: StepVerdict | null;
}

export interface Outcome {
  done: number;
  skipped: number;
  failed: number;
  unresolved: number;
  freed: number;
  quarantine: string | null;
  sourceWasUnfinished: boolean;
}

/**
 * Runs one stage of the pipeline.
 *
 * The window shows that it is busy, catches whatever went wrong and says so, so
 * no screen has to remember to do either.
 */
export type Runner = <T>(work: () => Promise<T>, then: (result: T) => void) => void;

export type Phase = "walking" | "sampling" | "reading" | "operating";

export interface Report {
  phase: Phase;
  subject: string;
  done: number;
  total: number | null;
  unread: number;
}

export const begin = () => invoke<Beginning>("begin");
export const scan = (roots: string[]) => invoke<Inventory>("scan", { roots });
export const analyze = (thorough: boolean) => invoke<Findings>("analyze", { thorough });
export const groups = (offset: number, limit: number) =>
  invoke<GroupRow[]>("groups", { offset, limit });
export const copies = (group: number) => invoke<Copy[]>("copies", { group });
export const plan = (keep: string, prefer: string | null) =>
  invoke<Step[]>("plan", { keep, prefer });
export const preflight = (fast: boolean) => invoke<Step[]>("preflight", { fast });
export const apply = () => invoke<Outcome>("apply");
export const undo = () => invoke<Outcome>("undo");

/** Subscribes to progress. The returned function stops listening. */
export function watchProgress(onReport: (report: Report) => void) {
  return listen<Report>("scrub://progress", (event) => onReport(event.payload));
}

/** Whatever the Rust side said, as a string the window can show. */
export function messageOf(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return String(error);
}
