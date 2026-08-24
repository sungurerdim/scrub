// The first screen: what this machine synchronises, and what it does not.
//
// The order is the argument. Before any number about duplicates or space, the
// screen says which folders sit inside a cloud directory without being backed
// up — the one thing here that is both consequential and invisible in a file
// browser. Everything else can wait until somebody has read that.

import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import type { Beginning, Inventory, Runner } from "./api";
import * as api from "./api";
import * as format from "./format";
import { Survey } from "./Survey";
import { Button, Card, Figure, Nothing, Path } from "./parts";

export function Discover({
  beginning,
  inventory,
  busy,
  run,
  onScanned,
}: {
  beginning: Beginning;
  inventory: Inventory | null;
  busy: boolean;
  run: Runner;
  onScanned: (found: Inventory) => void;
}) {
  const [roots, setRoots] = useState<string[]>([]);
  const { providers } = beginning;
  const scanning = roots.length > 0 ? roots : [beginning.home];

  async function choose() {
    const picked = await open({ directory: true, multiple: true });
    if (Array.isArray(picked)) setRoots(picked);
    else if (typeof picked === "string") setRoots([picked]);
  }

  function scan() {
    run(() => api.scan(roots), onScanned);
  }

  return (
    <div className="space-y-5">
      {providers.notBackedUp.length > 0 && (
        <Card
          tone="warn"
          title={`${providers.notBackedUp.length} folder(s) inside a cloud directory are not being backed up`}
          hint="The provider marked these links as excluded from sync. In a file browser they look like everything else in the cloud folder."
        >
          <ul className="space-y-3">
            {providers.notBackedUp.map((link) => (
              <li key={link.link}>
                <Path>{link.target}</Path>
                <div className="mt-0.5 text-xs text-dim">
                  linked from <Path>{link.link}</Path>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {providers.unsettled.length > 0 && (
        <Card
          title={`${providers.unsettled.length} link(s) lead somewhere nothing here can settle`}
          hint="They point outside every provider this machine knows about. Whether their contents are backed up is not something this machine can answer either way, so it does not guess."
        >
          <ul className="space-y-1">
            {providers.unsettled.map((link) => (
              <li key={link.link}>
                <Path>{`${link.link} → ${link.target}`}</Path>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card
        title={`${providers.roots.length} provider ${providers.roots.length === 1 ? "directory" : "directories"} detected`}
        hint={
          providers.providerOwned > 0
            ? `${providers.providerOwned} link(s) lead into a provider's own storage, which is ordinary.`
            : undefined
        }
      >
        {providers.roots.length === 0 ? (
          <Nothing>Nothing on this machine is being synchronised to a cloud.</Nothing>
        ) : (
          <ul className="divide-y divide-edge/60">
            {providers.roots.map((root) => (
              <li key={root.path} className="flex items-baseline gap-3 py-2 first:pt-0">
                <span className="w-28 shrink-0 text-sm text-ink">{root.provider}</span>
                <div className="min-w-0 flex-1">
                  <Path>{root.path}</Path>
                  <div className="mt-0.5 text-xs text-dim">
                    {root.origin}
                    {root.account ? ` · ${root.account}` : ""}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card
        title="Record what is here"
        hint="Nothing is opened, downloaded or changed. A file that lives in the cloud stays there: the scan reads what the filesystem already knows about it."
      >
        <div className="flex flex-wrap items-center gap-3">
          <Button onClick={choose} disabled={busy}>
            Choose folders…
          </Button>
          <Button onClick={scan} kind="primary" disabled={busy}>
            {inventory ? "Scan again" : "Scan"}
          </Button>
          {roots.length > 0 && (
            <Button onClick={() => setRoots([])} disabled={busy}>
              Reset to home folder
            </Button>
          )}
        </div>
        <ul className="mt-3 space-y-1">
          {scanning.map((root) => (
            <li key={root}>
              <Path>{root}</Path>
            </li>
          ))}
        </ul>
      </Card>

      {inventory && <Found inventory={inventory} />}
      {inventory && <Survey busy={busy} run={run} />}
    </div>
  );
}

function Found({ inventory }: { inventory: Inventory }) {
  const [showUnread, setShowUnread] = useState(false);

  return (
    <Card title="What the scan found">
      <div className="grid grid-cols-2 gap-6 sm:grid-cols-4">
        <Figure value={format.count(inventory.files)} name="files" />
        <Figure value={format.count(inventory.directories)} name="folders" />
        <Figure value={format.bytes(inventory.bytes)} name="on this disk" />
        <Figure
          value={format.count(inventory.inCloud)}
          name="in the cloud, not on this disk"
          tone="accent"
        />
      </div>

      {inventory.links > 0 && (
        <p className="mt-4 text-xs text-dim">
          {format.count(inventory.links)} symbolic link(s) were recorded and none were
          followed, so nothing was counted twice.
        </p>
      )}

      {inventory.unread.length > 0 && (
        <div className="mt-4 border-t border-edge/60 pt-4">
          <button
            type="button"
            onClick={() => setShowUnread(!showUnread)}
            className="text-xs text-warn hover:underline"
          >
            {showUnread ? "Hide" : "Show"} {inventory.unread.length} place(s) that could
            not be read
          </button>
          <p className="mt-1 text-xs text-dim">
            These are not counted above, and they are not reported as empty.
          </p>
          {showUnread && (
            <ul className="mt-3 max-h-60 space-y-2 overflow-y-auto">
              {inventory.unread.map((unread) => (
                <li key={unread.path}>
                  <Path>{unread.path}</Path>
                  <div className="text-xs text-dim">{unread.reason}</div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Card>
  );
}
