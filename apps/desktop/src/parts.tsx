// The small pieces every screen is built from.
//
// They are here rather than repeated because a button that looks slightly
// different on one screen reads as a different button, and this tool asks people
// to trust that the thing they press does what the last one did.

import type { ReactNode } from "react";

export function Button({
  children,
  onClick,
  kind = "quiet",
  disabled = false,
}: {
  children: ReactNode;
  onClick: () => void;
  kind?: "primary" | "quiet" | "danger";
  disabled?: boolean;
}) {
  const look =
    kind === "primary"
      ? "bg-accent text-accent-ink hover:brightness-110"
      : kind === "danger"
        ? "border border-alarm/60 text-alarm hover:bg-alarm/10"
        : "border border-edge text-ink hover:bg-raised";

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`rounded-lg px-4 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-40 ${look}`}
    >
      {children}
    </button>
  );
}

export function Card({
  title,
  hint,
  children,
  tone = "plain",
}: {
  title?: string | undefined;
  hint?: string | undefined;
  children: ReactNode;
  tone?: "plain" | "warn" | undefined;
}) {
  return (
    <section
      className={`rounded-xl border p-5 ${
        tone === "warn" ? "border-warn/40 bg-warn/5" : "border-edge bg-raised"
      }`}
    >
      {title && (
        <header className="mb-3">
          <h2 className={`text-sm font-semibold ${tone === "warn" ? "text-warn" : "text-ink"}`}>
            {title}
          </h2>
          {hint && <p className="mt-1 text-xs text-dim">{hint}</p>}
        </header>
      )}
      {children}
    </section>
  );
}

/** One number with its name under it. The name is a sentence, not a label. */
export function Figure({
  value,
  name,
  tone = "plain",
}: {
  value: string;
  name: string;
  tone?: "plain" | "accent" | "warn";
}) {
  const colour =
    tone === "accent" ? "text-accent" : tone === "warn" ? "text-warn" : "text-ink";
  return (
    <div>
      <div className={`text-2xl font-semibold tabular-nums ${colour}`}>{value}</div>
      <div className="mt-0.5 text-xs text-dim">{name}</div>
    </div>
  );
}

export function Path({ children }: { children: string }) {
  return (
    <code className="selectable font-mono text-xs break-all text-faded">{children}</code>
  );
}

/** What is shown where a list would be, when the list is empty on purpose. */
export function Nothing({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-sm text-dim">{children}</p>;
}

export function Trouble({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-alarm/50 bg-alarm/10 px-4 py-3">
      <p className="flex-1 text-sm text-ink">{message}</p>
      <button
        type="button"
        onClick={onDismiss}
        className="text-xs text-dim hover:text-ink"
        aria-label="Dismiss this message"
      >
        Dismiss
      </button>
    </div>
  );
}
