// Turning numbers into what a person reads.
//
// Sizes use the units a file browser uses, so a figure here can be compared
// with one there without arithmetic. Nothing is rounded up: a saving stated
// larger than it is would be the one lie this tool must not tell.

const UNITS = ["bytes", "KB", "MB", "GB", "TB", "PB"] as const;

export function bytes(value: number): string {
  if (value < 1000) return `${value} bytes`;
  let scaled = value;
  let unit = 0;
  while (scaled >= 1000 && unit < UNITS.length - 1) {
    scaled /= 1000;
    unit += 1;
  }
  // One decimal below 10, none above: "1.4 GB" is useful, "847.3 MB" is noise.
  const rounded = scaled < 10 ? Math.floor(scaled * 10) / 10 : Math.floor(scaled);
  return `${rounded} ${UNITS[unit]}`;
}

export function count(value: number): string {
  return value.toLocaleString();
}

export function when(seconds: number | null): string {
  if (seconds === null) return "not recorded";
  return new Date(seconds * 1000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

/** The last two parts of a path, which is usually enough to recognise it. */
export function shortPath(path: string): string {
  const parts = path.split("/").filter(Boolean);
  if (parts.length <= 2) return path;
  return `…/${parts.slice(-2).join("/")}`;
}
