// The last screen: the only one where anything happens.
//
// It shows every step, one line each, with what the disk said about it when it
// was checked. Then it asks — once, in words, with the number of files and the
// space involved — and only then does it run.
//
// Even then nothing is deleted. Files are moved into a quarantine folder that
// keeps each one's original path, and the record written while they move is
// what puts them back (DR-5, DR-10).

import { useState } from "react";
import type { Outcome, Runner, Step } from "./api";
import * as api from "./api";
import * as format from "./format";
import { Differences } from "./Arrange";
import { Button, Card, Figure, Nothing, Path, Trouble } from "./parts";

export function Apply({
  steps,
  outcome,
  busy,
  run,
  onChecked,
  onRan,
  onTrouble,
}: {
  steps: Step[] | null;
  outcome: Outcome | null;
  busy: boolean;
  run: Runner;
  onChecked: (checked: Step[]) => void;
  onRan: (came: Outcome | null) => void;
  onTrouble: (message: string) => void;
}) {
  const [fast, setFast] = useState(false);
  const [confirming, setConfirming] = useState(false);

  const checked = steps?.some((step) => step.verdict !== null) ?? false;
  const passing = steps?.filter((step) => step.verdict?.grade === "pass") ?? [];
  const held = steps?.filter((step) => step.verdict && step.verdict.grade !== "pass") ?? [];
  const frees = passing.reduce((total, step) => total + step.frees, 0);

  function check() {
    setConfirming(false);
    run(() => api.preflight(fast), onChecked);
  }

  function carryOut() {
    setConfirming(false);
    run(api.apply, onRan);
  }

  function reverse() {
    run(api.undo, onRan);
  }

  if (!steps) {
    return (
      <div className="space-y-5">
        <Differences onTrouble={onTrouble} />
        <Card title="Nothing to carry out yet">
          <Nothing>
            Decide what should happen first — choose which copy of a duplicate to keep,
            or rearrange something.
          </Nothing>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <Differences onTrouble={onTrouble} />
      <Card
        title="Check the plan against the disk"
        hint="Every file is looked at again and its contents read, to be sure it is still the file the plan was made about. Nothing is changed by checking."
      >
        <div className="flex flex-wrap items-center gap-3">
          <Button onClick={check} kind="primary" disabled={busy}>
            {checked ? "Check again" : "Check"}
          </Button>
          <label className="flex items-center gap-2 text-sm text-faded">
            <input
              type="checkbox"
              checked={fast}
              onChange={(event) => setFast(event.target.checked)}
              className="size-4 accent-[var(--color-accent)]"
            />
            Compare sizes and dates instead of reading contents
          </label>
        </div>
        <p className="mt-2 text-xs text-dim">
          The quick comparison catches anything an ordinary edit would do. It cannot
          catch a file swapped for another of exactly the same size with its date
          preserved.
        </p>
      </Card>

      {checked && (
        <Card title="What was checked">
          <div className="grid grid-cols-2 gap-6 sm:grid-cols-3">
            <Figure value={format.count(passing.length)} name="ready to run" tone="accent" />
            <Figure
              value={format.count(held.length)}
              name="held back"
              tone={held.length > 0 ? "warn" : "plain"}
            />
            <Figure value={format.bytes(frees)} name="would be freed" />
          </div>
          {held.length > 0 && (
            <p className="mt-4 border-t border-edge/60 pt-4 text-xs text-dim">
              A held step is a question, not a failure: the file moved, or something is
              already where it would go. Nothing held is carried out, and looking for
              duplicates again will settle it.
            </p>
          )}
        </Card>
      )}

      <Card
        title={checked ? "Every step, and what the disk said" : "Every step"}
        hint="Set aside means moved into a quarantine folder. Nothing is deleted."
      >
        <div className="max-h-96 space-y-2 overflow-y-auto">
          {steps.map((step) => (
            <Line key={step.index} step={step} />
          ))}
        </div>
      </Card>

      {checked && passing.length > 0 && !outcome && (
        <Card title="Carry it out">
          {confirming ? (
            <div className="space-y-4">
              <p className="text-sm text-ink">
                This will move {format.count(passing.length)} file
                {passing.length === 1 ? "" : "s"} into a quarantine folder, freeing{" "}
                {format.bytes(frees)}. Nothing is deleted, and every move is recorded so
                it can be put back.
              </p>
              <div className="flex gap-3">
                <Button onClick={carryOut} kind="primary" disabled={busy}>
                  Yes, move {format.count(passing.length)} file
                  {passing.length === 1 ? "" : "s"}
                </Button>
                <Button onClick={() => setConfirming(false)} disabled={busy}>
                  Not yet
                </Button>
              </div>
            </div>
          ) : (
            <Button onClick={() => setConfirming(true)} kind="primary" disabled={busy}>
              Carry out {format.count(passing.length)} step
              {passing.length === 1 ? "" : "s"}…
            </Button>
          )}
        </Card>
      )}

      {outcome && <Ran outcome={outcome} busy={busy} onUndo={reverse} />}
    </div>
  );
}

function Line({ step }: { step: Step }) {
  const grade = step.verdict?.grade;
  const edge =
    grade === "pass"
      ? "border-l-accent"
      : grade === "hold"
        ? "border-l-warn"
        : grade === "fail"
          ? "border-l-alarm"
          : "border-l-edge";

  return (
    <div className={`border-l-2 py-1.5 pl-3 ${edge}`}>
      <div className="flex items-baseline gap-2">
        <span className="text-xs text-faded">
          {step.kind === "quarantine"
            ? "set aside"
            : step.kind === "move"
              ? "move"
              : "make folder"}
        </span>
        <span className="min-w-0 flex-1">
          <Path>{step.subject || step.destination || ""}</Path>
        </span>
        {step.frees > 0 && (
          <span className="shrink-0 text-xs text-accent tabular-nums">
            {format.bytes(step.frees)}
          </span>
        )}
      </div>
      <div className="mt-0.5 text-xs text-dim">{step.because}</div>
      {step.verdict?.impediment && (
        <div className="mt-0.5 text-xs text-warn">
          held back: {step.verdict.impediment}
        </div>
      )}
    </div>
  );
}

function Ran({
  outcome,
  busy,
  onUndo,
}: {
  outcome: Outcome;
  busy: boolean;
  onUndo: () => void;
}) {
  return (
    <Card title="What happened">
      <div className="grid grid-cols-2 gap-6 sm:grid-cols-4">
        <Figure value={format.count(outcome.done)} name="changes made" tone="accent" />
        <Figure value={format.count(outcome.skipped)} name="skipped" />
        <Figure
          value={format.count(outcome.failed)}
          name="did not succeed"
          tone={outcome.failed > 0 ? "warn" : "plain"}
        />
        <Figure value={format.bytes(outcome.freed)} name="freed" />
      </div>

      {outcome.unresolved > 0 && (
        <div className="mt-4">
          <Trouble
            message={`${outcome.unresolved} step(s) were written down but never resolved, which means the run stopped part-way. Nothing is assumed about them: look at the record before doing anything else.`}
            onDismiss={() => undefined}
          />
        </div>
      )}

      {outcome.quarantine && (
        <p className="mt-4 text-xs text-dim">
          Everything that moved is here, under the path it had before:{" "}
          <Path>{outcome.quarantine}</Path>
        </p>
      )}

      <div className="mt-5 border-t border-edge/60 pt-4">
        <Button onClick={onUndo} kind="danger" disabled={busy}>
          Put everything back
        </Button>
        <p className="mt-2 text-xs text-dim">
          Reverses every move this run made, newest first, checking each file is the one
          it expects before touching it.
        </p>
      </div>
    </Card>
  );
}
