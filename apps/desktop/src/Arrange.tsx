// The third screen: rearranging everything, with nothing happening.
//
// A file browser on the left and a growing list of changes on the right. Every
// action here changes the picture and no disk: renaming a folder shows it under
// its new name and shows everything inside it having come along, and none of it
// is real until the last screen (DR-9).
//
// The interaction is the one people already know — pick things up, walk to
// where you want them, put them down — because a tool asking somebody to
// reorganize a lifetime of files should not also ask them to learn a new way of
// doing it.

import { useCallback, useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { Arranged, Edit, Item, Listing, Runner } from "./api";
import * as api from "./api";
import * as format from "./format";
import { Button, Card, Figure, Nothing, Path } from "./parts";

/** How many things are asked for at a time. */
const PAGE = 400;

export function Arrange({
  arranged,
  busy,
  run,
  onArranged,
  onTrouble,
}: {
  arranged: Arranged | null;
  busy: boolean;
  run: Runner;
  onArranged: (now: Arranged) => void;
  onTrouble: (message: string) => void;
}) {
  const [listing, setListing] = useState<Listing | null>(null);
  const [at, setAt] = useState<string | null>(null);
  const [chosen, setChosen] = useState<Set<number>>(new Set());
  const [carrying, setCarrying] = useState<Item[]>([]);
  const [naming, setNaming] = useState<"folder" | "rename" | null>(null);
  const [typed, setTyped] = useState("");

  const look = useCallback(
    (where: string | null) => {
      api
        .browse(where, 0, PAGE)
        .then((found) => {
          setListing(found);
          setAt(found.here);
          setChosen(new Set());
        })
        .catch((error: unknown) => onTrouble(api.messageOf(error)));
    },
    [onTrouble],
  );

  useEffect(() => {
    look(null);
  }, [look]);

  /** Makes one change, then redraws both the browser and the tally. */
  function change(edit: Edit) {
    run(
      async () => {
        const now = await api.arrange(edit);
        const again = await api.browse(at, 0, PAGE);
        return { now, again };
      },
      ({ now, again }) => {
        onArranged(now);
        setListing(again);
        setChosen(new Set());
        setNaming(null);
        setTyped("");
      },
    );
  }

  function takeBack() {
    run(
      async () => {
        const now = await api.takeBack();
        const again = await api.browse(at, 0, PAGE);
        return { now, again };
      },
      ({ now, again }) => {
        onArranged(now);
        setListing(again);
      },
    );
  }

  const picked = listing?.items.filter((item) => chosen.has(item.entry)) ?? [];
  const onlyOne = picked.length === 1 ? picked[0] : undefined;

  function putDown() {
    if (!at || carrying.length === 0) return;
    // One at a time, because each has to be told whether it worked. The first
    // refusal stops the rest: a half-applied batch is a state nobody asked for.
    const [first, ...rest] = carrying;
    if (!first) return;
    setCarrying(rest);
    change({ relocate: { entry: first.entry, into: at } });
  }

  return (
    <div className="space-y-5">
      <Card
        title="Rearrange it however you like"
        hint="Nothing here touches a file. Make folders, rename things, move them about; the next screen shows you the before and after and asks before any of it is real."
      >
        <div className="flex flex-wrap items-center gap-3">
          <Button
            onClick={() => {
              setNaming("folder");
              setTyped("");
            }}
            disabled={busy || !at}
          >
            New folder here
          </Button>
          <Button
            onClick={() => {
              setNaming("rename");
              setTyped(onlyOne?.name ?? "");
            }}
            disabled={busy || !onlyOne}
          >
            Rename
          </Button>
          <Button
            onClick={() => {
              setCarrying(picked);
              setChosen(new Set());
            }}
            disabled={busy || picked.length === 0}
          >
            Pick up {picked.length > 0 ? `(${picked.length})` : ""}
          </Button>
          <Button
            onClick={putDown}
            kind="primary"
            disabled={busy || carrying.length === 0}
          >
            Put down here {carrying.length > 0 ? `(${carrying.length})` : ""}
          </Button>
          <Button
            onClick={() => {
              for (const item of picked) {
                if (!item.isFolder) change({ set_aside: { entry: item.entry } });
              }
            }}
            disabled={busy || picked.length === 0 || picked.every((item) => item.isFolder)}
          >
            Set aside
          </Button>
          <div className="flex-1" />
          <Button onClick={takeBack} disabled={busy || (arranged?.asked ?? 0) === 0}>
            Take back the last change
          </Button>
        </div>

        {naming && (
          <form
            className="mt-4 flex items-center gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              if (naming === "folder" && at) {
                change({ new_directory: { path: joined(at, typed) } });
              } else if (naming === "rename" && onlyOne) {
                change({ rename: { entry: onlyOne.entry, to: typed } });
              }
            }}
          >
            <label className="text-sm text-faded" htmlFor="name">
              {naming === "folder" ? "Name the folder" : "New name"}
            </label>
            <input
              id="name"
              value={typed}
              autoFocus
              onChange={(event) => setTyped(event.target.value)}
              className="selectable flex-1 rounded-lg border border-edge bg-ground px-3 py-1.5 text-sm text-ink"
            />
            <Button onClick={() => undefined} kind="primary">
              {naming === "folder" ? "Make it" : "Rename"}
            </Button>
            <Button
              onClick={() => {
                setNaming(null);
                setTyped("");
              }}
            >
              Cancel
            </Button>
          </form>
        )}

        {carrying.length > 0 && (
          <p className="mt-3 text-xs text-accent">
            Carrying {carrying.length} thing{carrying.length === 1 ? "" : "s"}. Walk to
            where you want {carrying.length === 1 ? "it" : "them"} and put{" "}
            {carrying.length === 1 ? "it" : "them"} down.
          </p>
        )}
      </Card>

      {arranged && arranged.asked > 0 && (
        <Card title="So far">
          <div className="grid grid-cols-2 gap-6 sm:grid-cols-4">
            <Figure value={format.count(arranged.asked)} name="changes made" />
            <Figure
              value={format.count(arranged.differences)}
              name="things that would end up somewhere else"
              tone="accent"
            />
            <Figure value={format.count(arranged.newFolders)} name="folders to make" />
            <Figure value={format.count(arranged.setAside)} name="files set aside" />
          </div>
        </Card>
      )}

      <Browser
        listing={listing}
        chosen={chosen}
        busy={busy}
        onOpen={look}
        onChoose={(entry) => {
          const next = new Set(chosen);
          if (next.has(entry)) next.delete(entry);
          else next.add(entry);
          setChosen(next);
        }}
      />
    </div>
  );
}

function Browser({
  listing,
  chosen,
  busy,
  onOpen,
  onChoose,
}: {
  listing: Listing | null;
  chosen: Set<number>;
  busy: boolean;
  onOpen: (where: string | null) => void;
  onChoose: (entry: number) => void;
}) {
  const scroller = useRef<HTMLDivElement>(null);
  const items = listing?.items ?? [];

  const virtual = useVirtualizer({
    count: items.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => 40,
    overscan: 12,
  });

  return (
    <Card
      title={listing ? listing.here : "Looking…"}
      hint={
        listing && listing.total > items.length
          ? `Showing the first ${items.length} of ${format.count(listing.total)}.`
          : undefined
      }
    >
      <div className="mb-3 flex items-center gap-3">
        <Button
          onClick={() => onOpen(listing?.parent ?? null)}
          disabled={busy || !listing?.parent}
        >
          Up
        </Button>
        <Button onClick={() => onOpen(null)} disabled={busy}>
          Home
        </Button>
      </div>

      <div ref={scroller} className="max-h-[24rem] overflow-y-auto">
        {items.length === 0 ? (
          <Nothing>
            {listing
              ? "This folder holds nothing the scan recorded."
              : "Scan this machine first."}
          </Nothing>
        ) : (
          <div style={{ height: virtual.getTotalSize(), position: "relative" }}>
            {virtual.getVirtualItems().map((slot) => {
              const item = items[slot.index];
              if (!item) return null;
              return (
                <div
                  key={`${item.path}-${item.entry}`}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: slot.size,
                    transform: `translateY(${slot.start}px)`,
                  }}
                >
                  <Line
                    item={item}
                    chosen={chosen.has(item.entry)}
                    onOpen={onOpen}
                    onChoose={onChoose}
                  />
                </div>
              );
            })}
          </div>
        )}
      </div>
    </Card>
  );
}

function Line({
  item,
  chosen,
  onOpen,
  onChoose,
}: {
  item: Item;
  chosen: boolean;
  onOpen: (where: string) => void;
  onChoose: (entry: number) => void;
}) {
  return (
    <div
      className={`flex h-10 items-center gap-3 rounded px-2 ${
        chosen ? "bg-accent/10" : "hover:bg-ground/40"
      }`}
    >
      <input
        type="checkbox"
        checked={chosen}
        // A folder that only exists in the arrangement has no entry to name, so
        // it can be walked into but not picked up.
        disabled={item.entry === Number.MAX_SAFE_INTEGER || item.entry < 0}
        onChange={() => onChoose(item.entry)}
        className="size-4 shrink-0 accent-[var(--color-accent)]"
        aria-label={`Choose ${item.name}`}
      />
      <button
        type="button"
        onClick={() => item.isFolder && onOpen(item.path)}
        className="flex min-w-0 flex-1 items-baseline gap-2 text-left"
      >
        <span className="shrink-0 text-xs text-dim">{item.isFolder ? "▸" : " "}</span>
        <span className="min-w-0 flex-1 truncate text-sm text-ink">{item.name}</span>
        {item.moved && <span className="shrink-0 text-xs text-accent">moved</span>}
        {!item.local && <span className="shrink-0 text-xs text-dim">in the cloud</span>}
        {!item.isFolder && (
          <span className="shrink-0 text-xs text-faded tabular-nums">
            {format.bytes(item.size)}
          </span>
        )}
      </button>
    </div>
  );
}

/** Joins a folder and a typed name without inventing a separator rule. */
function joined(folder: string, name: string): string {
  const trimmed = name.trim();
  return folder.endsWith("/") ? `${folder}${trimmed}` : `${folder}/${trimmed}`;
}

/** The old arrangement beside the new one. */
export function Differences({ onTrouble }: { onTrouble: (message: string) => void }) {
  const [lines, setLines] = useState<api.Difference[] | null>(null);
  const [showCarried, setShowCarried] = useState(false);

  useEffect(() => {
    api
      .differences(0, 2000)
      .then(setLines)
      .catch((error: unknown) => onTrouble(api.messageOf(error)));
  }, [onTrouble]);

  if (!lines || lines.length === 0) return null;

  const decided = lines.filter((line) => !line.carried);
  const carried = lines.filter((line) => line.carried);
  const shown = showCarried ? lines : decided;

  return (
    <Card
      title="Before and after"
      hint="Everything that would end up somewhere other than where it is now. This is what the next step asks you to approve."
    >
      <div className="max-h-96 space-y-2 overflow-y-auto">
        {shown.map((line) => (
          <div key={`${line.entry}-${line.was}`} className="text-xs">
            <Path>{line.was}</Path>
            <div className="mt-0.5 pl-4">
              {line.becomes === null ? (
                <span className="text-warn">set aside, not deleted</span>
              ) : (
                <span className="text-accent">→ {line.becomes}</span>
              )}
              {line.carried && (
                <span className="ml-2 text-dim">came with the folder above it</span>
              )}
            </div>
          </div>
        ))}
      </div>

      {carried.length > 0 && (
        <button
          type="button"
          onClick={() => setShowCarried(!showCarried)}
          className="mt-3 text-xs text-dim hover:text-ink"
        >
          {showCarried ? "Hide" : "Show"} {format.count(carried.length)} thing
          {carried.length === 1 ? "" : "s"} that came along with a folder
        </button>
      )}
    </Card>
  );
}
