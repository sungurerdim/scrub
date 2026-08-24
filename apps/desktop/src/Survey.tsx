// Where the space went, and what it went on.
//
// The answer to the question somebody actually opened the tool with. Counting
// files does not answer it; naming the four folders holding most of the space
// does, and so does saying plainly how much of what you appear to own is not
// actually on this machine.
//
// Three sections, in the order a person reads them: how much there is and where
// it lives, what kind of thing it is, and then the specific folders and files to
// go and look at.

import { useState } from "react";
import type { Runner, Survey as Found } from "./api";
import * as api from "./api";
import * as format from "./format";
import { Button, Card, Figure, Path } from "./parts";

export function Survey({ busy, run }: { busy: boolean; run: Runner }) {
  const [found, setFound] = useState<Found | null>(null);

  if (!found) {
    return (
      <Card
        title="Where has the space gone?"
        hint="Worked out from what the scan already recorded — nothing is opened, and nothing is downloaded."
      >
        <Button onClick={() => run(api.survey, setFound)} disabled={busy}>
          Work it out
        </Button>
      </Card>
    );
  }

  const share = (bytes: number) => (found.bytes > 0 ? bytes / found.bytes : 0);

  return (
    <div className="space-y-5">
      <Card title="Where has the space gone?">
        <div className="grid grid-cols-2 gap-6 sm:grid-cols-3">
          <Figure value={format.bytes(found.hereBytes)} name="on this disk" />
          <Figure
            value={format.bytes(found.cloudBytes)}
            name={`in the cloud, not on this disk (${format.count(found.cloudFiles)} files)`}
            tone="accent"
          />
          <Figure value={format.count(found.files)} name="files altogether" />
        </div>
        {found.cloudBytes > 0 && (
          <p className="mt-4 text-xs text-dim">
            The two figures are kept apart on purpose. Adding them gives a number that
            is true of nothing: not of this disk, and not of what you can open today.
          </p>
        )}
      </Card>

      <Card
        title="What kind of things are here"
        hint="Judged by each file's name and where it sits, not by opening it — settling that would mean reading every file, and reading the ones in the cloud would download them."
      >
        <ul className="space-y-2">
          {found.kinds.map((kind) => (
            <li key={kind.name}>
              <div className="flex items-baseline gap-3">
                <span className="w-32 shrink-0 text-sm text-ink">{kind.name}</span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-ground">
                  <div
                    className={`h-full ${kind.personal ? "bg-accent" : "bg-dim"}`}
                    style={{ width: `${Math.max(share(kind.bytes) * 100, 0.5)}%` }}
                  />
                </div>
                <span className="w-24 shrink-0 text-right text-sm text-faded tabular-nums">
                  {format.bytes(kind.bytes)}
                </span>
                <span className="w-20 shrink-0 text-right text-xs text-dim tabular-nums">
                  {format.count(kind.files)}
                </span>
              </div>
            </li>
          ))}
        </ul>
        <p className="mt-4 text-xs text-dim">
          The grey rows belong to the machine rather than to you — programs, caches,
          libraries. Tidying those breaks things, so this tool leaves them alone.
        </p>
      </Card>

      <Card
        title="The folders holding the most"
        hint="Each one counts everything nested inside it. A folder whose weight is entirely explained by one folder inside it is left out, so this is where the space actually divides."
      >
        <ul className="space-y-2">
          {found.folders.slice(0, 15).map((folder) => (
            <li key={folder.path} className="flex items-baseline gap-3">
              <div className="min-w-0 flex-1">
                <Path>{folder.path}</Path>
                <div className="mt-0.5 text-xs text-dim">
                  {format.count(folder.files)} files
                </div>
              </div>
              <span className="shrink-0 text-sm text-accent tabular-nums">
                {format.bytes(folder.bytes)}
              </span>
            </li>
          ))}
        </ul>
      </Card>

      <Card title="The largest single files">
        <ul className="space-y-2">
          {found.largest.slice(0, 15).map((file) => (
            <li key={file.path} className="flex items-baseline gap-3">
              <div className="min-w-0 flex-1">
                <Path>{file.path}</Path>
                <div className="mt-0.5 text-xs text-dim">
                  {file.kind}
                  {!file.local && " · in the cloud, so setting it aside frees nothing here"}
                </div>
              </div>
              <span className="shrink-0 text-sm text-faded tabular-nums">
                {format.bytes(file.bytes)}
              </span>
            </li>
          ))}
        </ul>
      </Card>

      <div>
        <Button onClick={() => setFound(null)} disabled={busy}>
          Hide
        </Button>
      </div>
    </div>
  );
}
