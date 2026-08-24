// The window itself: three steps, in order, and what is happening right now.
//
// The steps are always visible and never guessed at. A step whose input does
// not exist yet is shown greyed rather than hidden, because a person who cannot
// see what comes next cannot tell whether they have finished.

import { useEffect, useState } from "react";
import type { Beginning, Findings, Inventory, Outcome, Report, Step } from "./api";
import * as api from "./api";
import * as format from "./format";
import { Apply } from "./Apply";
import { Discover } from "./Discover";
import { Organize } from "./Organize";
import { Trouble } from "./parts";

type Screen = "discover" | "organize" | "apply";

const SCREENS: { id: Screen; name: string; below: string }[] = [
  { id: "discover", name: "Discover", below: "what is here, and what is not backed up" },
  { id: "organize", name: "Organize", below: "what is duplicated, and what to do" },
  { id: "apply", name: "Apply", below: "check it, then carry it out" },
];

export function App() {
  const [beginning, setBeginning] = useState<Beginning | null>(null);
  const [screen, setScreen] = useState<Screen>("discover");
  const [trouble, setTrouble] = useState<string | null>(null);

  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [findings, setFindings] = useState<Findings | null>(null);
  const [steps, setSteps] = useState<Step[] | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [token, setToken] = useState(0);

  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<Report | null>(null);

  useEffect(() => {
    api.begin().then(setBeginning).catch((error: unknown) => {
      setTrouble(api.messageOf(error));
    });
  }, []);

  useEffect(() => {
    const stopping = api.watchProgress(setReport);
    return () => {
      void stopping.then((stop) => {
        stop();
      });
    };
  }, []);

  /** Runs one stage, keeping the window honest about being busy.
   *
   * Every stage goes through here, so there is one place that knows work is
   * happening, one place that catches what went wrong, and no screen that can
   * forget to say either.
   */
  function run<T>(work: () => Promise<T>, then: (result: T) => void) {
    setBusy(true);
    setReport(null);
    setTrouble(null);
    work()
      .then(then)
      .catch((error: unknown) => {
        setTrouble(api.messageOf(error));
      })
      .finally(() => {
        setBusy(false);
        setReport(null);
      });
  }

  if (!beginning) {
    return (
      <main className="flex h-full items-center justify-center">
        {trouble ? (
          <div className="max-w-lg p-8">
            <Trouble message={trouble} onDismiss={() => setTrouble(null)} />
          </div>
        ) : (
          <p className="text-sm text-dim">Looking at what this machine synchronises…</p>
        )}
      </main>
    );
  }

  const reached: Record<Screen, boolean> = {
    discover: true,
    organize: inventory !== null || beginning.ready.includes("scan"),
    apply: steps !== null || beginning.ready.includes("plan"),
  };

  return (
    <div className="flex h-full flex-col">
      <header className="border-b border-edge bg-raised/60 px-6 py-3">
        <nav className="flex items-center gap-1">
          {SCREENS.map((option, index) => (
            <button
              key={option.id}
              type="button"
              onClick={() => setScreen(option.id)}
              disabled={!reached[option.id] || busy}
              className={`rounded-lg px-4 py-2 text-left transition disabled:cursor-not-allowed disabled:opacity-35 ${
                screen === option.id ? "bg-ground" : "hover:bg-ground/50"
              }`}
            >
              <span className="block text-sm font-medium">
                <span className="mr-2 text-dim tabular-nums">{index + 1}</span>
                {option.name}
              </span>
              <span className="block text-xs text-dim">{option.below}</span>
            </button>
          ))}
        </nav>
      </header>

      {busy && <Doing report={report} />}

      <main className="flex-1 overflow-y-auto px-6 py-6">
        <div className="mx-auto max-w-4xl space-y-5">
          {trouble && <Trouble message={trouble} onDismiss={() => setTrouble(null)} />}

          {screen === "discover" && (
            <Discover
              beginning={beginning}
              inventory={inventory}
              busy={busy}
              run={run}
              onScanned={(found) => {
                setInventory(found);
                setFindings(null);
                setSteps(null);
                setOutcome(null);
                setScreen("organize");
              }}
            />
          )}

          {screen === "organize" && (
            <Organize
              findings={findings}
              steps={steps}
              busy={busy}
              token={token}
              run={run}
              onAnalyzed={(found) => {
                setFindings(found);
                setSteps(null);
                setOutcome(null);
                setToken((was) => was + 1);
              }}
              onPlanned={(drafted) => {
                setSteps(drafted);
                setOutcome(null);
              }}
              onTrouble={setTrouble}
            />
          )}

          {screen === "apply" && (
            <Apply
              steps={steps}
              outcome={outcome}
              busy={busy}
              run={run}
              onChecked={setSteps}
              onRan={setOutcome}
            />
          )}
        </div>
      </main>

      <footer className="border-t border-edge px-6 py-2 text-xs text-dim">
        Artifacts are kept in <span className="selectable font-mono">{beginning.workspace}</span>
      </footer>
    </div>
  );
}

/** What is happening right now, while it happens. */
function Doing({ report }: { report: Report | null }) {
  const said = describe(report);
  const proportion =
    report && report.total && report.total > 0
      ? Math.min(1, report.done / report.total)
      : null;

  return (
    <div className="border-b border-edge bg-ground px-6 py-2">
      <div className="mx-auto flex max-w-4xl items-center gap-4">
        <span className="text-xs text-faded">{said}</span>
        <div className="h-1 flex-1 overflow-hidden rounded-full bg-raised">
          <div
            className={`h-full bg-accent ${proportion === null ? "animate-pulse w-1/3" : ""}`}
            style={proportion === null ? undefined : { width: `${proportion * 100}%` }}
          />
        </div>
      </div>
    </div>
  );
}

function describe(report: Report | null): string {
  if (!report) return "Working…";
  switch (report.phase) {
    case "walking":
      return `Looking: ${format.count(report.done)} found${
        report.unread > 0 ? `, ${format.count(report.unread)} unreadable` : ""
      }`;
    case "sampling":
      return `Comparing: ${format.count(report.done)} of ${format.count(report.total ?? 0)}`;
    case "reading":
      return `Reading in full: ${format.count(report.done)} of ${format.count(report.total ?? 0)}`;
    case "operating":
      return `Moving: ${format.count(report.done)} of ${format.count(report.total ?? 0)}`;
  }
}

