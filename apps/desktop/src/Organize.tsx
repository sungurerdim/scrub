// The second screen: what is duplicated, and what to do about it.
//
// A group of identical files is one row, whatever it holds — that is the rule
// this screen exists to keep (DR-21). Opening a row asks the Rust side for its
// copies; nothing else on the screen changes. The list is virtualised because
// a real machine produces tens of thousands of these rows and a browser that
// draws them all stops responding.
//
// Nothing here touches a file. Choosing a rule redraws a plan, and a plan is a
// list of intentions that can be thrown away by choosing another one.

import { useCallback, useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { Copy, Findings, GroupRow, Runner, Step } from "./api";
import * as api from "./api";
import * as format from "./format";
import { Button, Card, Figure, Nothing, Path } from "./parts";

/** How many rows are asked for at a time. */
const PAGE = 500;

const RULES = [
  {
    id: "oldest",
    name: "Keep the oldest",
    why: "The first one written is usually the original, and the later ones the copies.",
  },
  {
    id: "newest",
    name: "Keep the newest",
    why: "The most recently changed one, for folders where the latest is the one you work in.",
  },
  {
    id: "shallowest",
    name: "Keep the one nearest the top",
    why: "The copy with the fewest folders above it, which is usually where you filed it.",
  },
] as const;

export function Organize({
  findings,
  steps,
  busy,
  token,
  run,
  onAnalyzed,
  onPlanned,
  onTrouble,
}: {
  findings: Findings | null;
  steps: Step[] | null;
  busy: boolean;
  /** Changes whenever a fresh analysis arrives, which discards the rows below. */
  token: number;
  run: Runner;
  onAnalyzed: (found: Findings) => void;
  onPlanned: (drafted: Step[]) => void;
  onTrouble: (message: string) => void;
}) {
  const [thorough, setThorough] = useState(false);
  const [rule, setRule] = useState<string>("oldest");

  function analyze() {
    run(() => api.analyze(thorough), onAnalyzed);
  }

  function draft(chosen: string) {
    setRule(chosen);
    run(() => api.plan(chosen, null), onPlanned);
  }

  return (
    <div className="space-y-5">
      <Card
        title="Look for duplicates"
        hint="Files are compared by their contents and by nothing else. Two files with the same bytes are the same file whatever their names or dates say, and two files with different bytes are not, however alike they look."
      >
        <div className="flex flex-wrap items-center gap-3">
          <Button onClick={analyze} kind="primary" disabled={busy}>
            {findings ? "Look again" : "Look for duplicates"}
          </Button>
          <label className="flex items-center gap-2 text-sm text-faded">
            <input
              type="checkbox"
              checked={thorough}
              onChange={(event) => setThorough(event.target.checked)}
              className="size-4 accent-[var(--color-accent)]"
            />
            Read every file, not only the ones that could be duplicates
          </label>
        </div>
        <p className="mt-2 text-xs text-dim">
          Reading every file takes much longer and is only needed before comparing this
          machine with another one.
        </p>
      </Card>

      {findings && <Summary findings={findings} />}
      {findings && findings.proven > 0 && (
        <Groups key={token} onTrouble={onTrouble} />
      )}

      {findings && findings.proven > 0 && (
        <Card
          title="Which copy should be kept?"
          hint="Every other copy is set aside in a quarantine folder, not deleted. Nothing happens yet — this only draws up a list."
        >
          <div className="space-y-2">
            {RULES.map((option) => (
              <label
                key={option.id}
                className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition ${
                  rule === option.id
                    ? "border-accent/60 bg-accent/5"
                    : "border-edge hover:bg-ground/40"
                }`}
              >
                <input
                  type="radio"
                  name="keep"
                  checked={rule === option.id}
                  onChange={() => draft(option.id)}
                  disabled={busy}
                  className="mt-0.5 size-4 accent-[var(--color-accent)]"
                />
                <span>
                  <span className="block text-sm text-ink">{option.name}</span>
                  <span className="block text-xs text-dim">{option.why}</span>
                </span>
              </label>
            ))}
          </div>
        </Card>
      )}

      {steps && <Drafted steps={steps} />}
    </div>
  );
}

function Summary({ findings }: { findings: Findings }) {
  return (
    <Card title="What was proven">
      <div className="grid grid-cols-2 gap-6 sm:grid-cols-3">
        <Figure value={format.count(findings.proven)} name="groups proven identical" />
        <Figure value={format.count(findings.redundant)} name="redundant copies" />
        <Figure
          value={format.bytes(findings.reclaimable)}
          name="would be freed by keeping one of each"
          tone="accent"
        />
      </div>
      {findings.unchecked > 0 && (
        <p className="mt-4 border-t border-edge/60 pt-4 text-xs text-dim">
          {format.count(findings.unchecked)} group(s) could not be checked, because their
          contents are not on this machine. They are not counted above.
          {findings.toSettle > 0 &&
            ` Settling them would download ${format.bytes(findings.toSettle)}.`}
        </p>
      )}
    </Card>
  );
}

function Groups({ onTrouble }: { onTrouble: (message: string) => void }) {
  const [rows, setRows] = useState<GroupRow[]>([]);
  const [exhausted, setExhausted] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const scroller = useRef<HTMLDivElement>(null);

  const fetchMore = useCallback(async () => {
    try {
      const next = await api.groups(rows.length, PAGE);
      if (next.length < PAGE) setExhausted(true);
      setRows((have) => [...have, ...next]);
    } catch (error) {
      onTrouble(api.messageOf(error));
      setExhausted(true);
    }
  }, [rows.length, onTrouble]);

  useEffect(() => {
    if (rows.length === 0 && !exhausted) void fetchMore();
  }, [rows.length, exhausted, fetchMore]);

  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => 56,
    overscan: 12,
  });

  return (
    <Card
      title="Duplicate groups"
      hint="One row for each set of identical files, largest saving first. Open a row to see where its copies are."
    >
      <div ref={scroller} className="max-h-[26rem] overflow-y-auto">
        {rows.length === 0 ? (
          <Nothing>Nothing yet.</Nothing>
        ) : (
          <div style={{ height: virtual.getTotalSize(), position: "relative" }}>
            {virtual.getVirtualItems().map((item) => {
              const row = rows[item.index];
              if (!row) return null;
              return (
                <div
                  key={row.index}
                  ref={virtual.measureElement}
                  data-index={item.index}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    transform: `translateY(${item.start}px)`,
                  }}
                >
                  <Row
                    row={row}
                    open={open === row.index}
                    onToggle={() => setOpen(open === row.index ? null : row.index)}
                    onTrouble={onTrouble}
                  />
                </div>
              );
            })}
          </div>
        )}
      </div>

      {!exhausted && rows.length > 0 && (
        <div className="mt-3 text-center">
          <Button onClick={() => void fetchMore()}>Show more</Button>
        </div>
      )}
    </Card>
  );
}

function Row({
  row,
  open,
  onToggle,
  onTrouble,
}: {
  row: GroupRow;
  open: boolean;
  onToggle: () => void;
  onTrouble: (message: string) => void;
}) {
  const [inside, setInside] = useState<Copy[] | null>(null);

  useEffect(() => {
    if (!open || inside) return;
    api
      .copies(row.index)
      .then(setInside)
      .catch((error: unknown) => onTrouble(api.messageOf(error)));
  }, [open, inside, row.index, onTrouble]);

  return (
    <div className="border-b border-edge/50">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center gap-3 py-3 text-left hover:bg-ground/40"
        aria-expanded={open}
      >
        <span className="w-4 text-xs text-dim">{open ? "▾" : "▸"}</span>
        <span className="min-w-0 flex-1 truncate text-sm text-ink">{row.name}</span>
        <span className="w-24 shrink-0 text-right text-xs text-faded tabular-nums">
          {row.copies} copies
        </span>
        <span className="w-24 shrink-0 text-right text-xs text-faded tabular-nums">
          {format.bytes(row.size)} each
        </span>
        <span className="w-28 shrink-0 text-right text-sm text-accent tabular-nums">
          {format.bytes(row.reclaimable)}
        </span>
      </button>

      {open && (
        <div className="pb-3 pl-7">
          {inside === null ? (
            <p className="text-xs text-dim">Reading…</p>
          ) : (
            <ul className="space-y-2">
              {inside.map((copy) => (
                <li key={copy.path} className="text-xs">
                  <Path>{copy.path}</Path>
                  <div className="mt-0.5 text-dim">
                    changed {format.when(copy.modified)} · created{" "}
                    {format.when(copy.created)}
                    {!copy.local && " · in the cloud, not on this disk"}
                    {copy.sameFile && " · another name for the copy above, freeing nothing"}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

function Drafted({ steps }: { steps: Step[] }) {
  const frees = steps.reduce((total, step) => total + step.frees, 0);
  const setAside = steps.filter((step) => step.kind === "quarantine").length;

  return (
    <Card
      title="What this would do"
      hint="Still nothing has happened. This is the list, and it is thrown away by choosing another rule."
    >
      <div className="grid grid-cols-2 gap-6 sm:grid-cols-3">
        <Figure value={format.count(setAside)} name="files set aside" />
        <Figure value={format.bytes(frees)} name="freed" tone="accent" />
        <Figure value={format.count(steps.length)} name="steps in total" />
      </div>
      <p className="mt-4 text-xs text-dim">
        Set aside means moved into a quarantine folder that keeps each file's original
        path. Nothing is deleted, here or at any later step.
      </p>
    </Card>
  );
}
