// pages.js -- pure helpers behind the "Estructura del documento" page groups
// and the "Recortes" card (T22). No DOM access here: everything takes plain
// data (the `pages` array of the analysis report) and returns plain data or
// strings, so the logic can be reasoned about (and reused) independently of
// render.js, which turns the results into elements with textContent only.

/** Tolerance, in points, when comparing box coordinates and paper sizes. */
const BOX_TOLERANCE = 0.5;
const PAPER_TOLERANCE = 2;

/** Well-known paper sizes in points, short side first. */
const PAPER_SIZES = [
  { name: "A5", short: 420, long: 595 },
  { name: "A4", short: 595, long: 842 },
  { name: "A3", short: 842, long: 1191 },
  { name: "A2", short: 1191, long: 1684 },
  { name: "Letter", short: 612, long: 792 },
  { name: "Legal", short: 612, long: 1008 },
];

const ORIENTATION_TEXT = { PORTRAIT: "Vertical", LANDSCAPE: "Horizontal", SQUARE: "Cuadrada" };

/** Name of a well-known paper size (either orientation, +-2 pt), or null. */
export function paperName(width, height) {
  const short = Math.min(width, height);
  const long = Math.max(width, height);
  const match = PAPER_SIZES.find(
    (paper) => Math.abs(paper.short - short) <= PAPER_TOLERANCE && Math.abs(paper.long - long) <= PAPER_TOLERANCE,
  );
  return match ? match.name : null;
}

/** [1, 2, 3, 7, 9, 10] -> "1–3, 7, 9–10" (en dash). Input order and duplicates do not matter. */
export function formatPageRanges(numbers) {
  const sorted = [...new Set(numbers)].sort((a, b) => a - b);
  const parts = [];
  let start = null;
  let previous = null;
  const flush = () => {
    if (start === null) return;
    parts.push(start === previous ? String(start) : `${start}–${previous}`);
  };
  for (const n of sorted) {
    if (previous !== null && n === previous + 1) {
      previous = n;
      continue;
    }
    flush();
    start = n;
    previous = n;
  }
  flush();
  return parts.join(", ");
}

function rotationDegrees(rotation) {
  const match = /^DEG_(\d+)$/.exec(rotation);
  return match ? Number(match[1]) : 0;
}

/**
 * Groups pages sharing rotation and size, in a single pass and in order of
 * first appearance. A page with an invalid /Rotate keeps its own group per raw
 * value, so it is never merged with a valid one.
 */
export function groupPagesBySize(pages) {
  const groups = new Map();
  for (const page of pages) {
    const width = Math.round(page.mediaBox.width);
    const height = Math.round(page.mediaBox.height);
    const key = page.rotationValid
      ? `${page.rotation}|${width}x${height}`
      : `invalid:${page.rawRotation}|${width}x${height}`;
    let group = groups.get(key);
    if (!group) {
      group = {
        numbers: [],
        width,
        height,
        orientation: page.orientation,
        rotationValid: page.rotationValid,
        rawRotation: page.rawRotation,
        degrees: rotationDegrees(page.rotation),
      };
      groups.set(key, group);
    }
    group.numbers.push(page.number);
  }
  return [...groups.values()];
}

/** "1 página" / "13 páginas". */
export function pageCountText(count) {
  return count === 1 ? "1 página" : `${count} páginas`;
}

/** Summary line of a group, e.g. "13 páginas · 595 × 842 pt (A4) · Vertical · 0°". */
export function describeGroup(group) {
  const paper = paperName(group.width, group.height);
  const size = `${group.width} × ${group.height} pt${paper ? ` (${paper})` : ""}`;
  const orientation = ORIENTATION_TEXT[group.orientation] || group.orientation;
  const rotation = group.rotationValid
    ? `${group.degrees}°`
    : `${group.rawRotation}° (no válida, se trata como ${group.degrees}°)`;
  return [pageCountText(group.numbers.length), size, orientation, rotation].join(" · ");
}

function sameBox(a, b) {
  return (
    Math.abs(a.llx - b.llx) <= BOX_TOLERANCE &&
    Math.abs(a.lly - b.lly) <= BOX_TOLERANCE &&
    Math.abs(a.urx - b.urx) <= BOX_TOLERANCE &&
    Math.abs(a.ury - b.ury) <= BOX_TOLERANCE
  );
}

const round1 = (value) => Math.round(value * 10) / 10;
const cropped = (value) => Math.max(0, round1(value));

/**
 * Pages whose CropBox differs from the MediaBox (0.5 pt tolerance), grouped by
 * identical media/crop geometry. Each group carries the page numbers, the
 * media and visible sizes and the amount cropped on every side, in points.
 */
export function findCropGroups(pages) {
  const groups = new Map();
  for (const page of pages) {
    const media = page.mediaBox;
    const crop = page.cropBox;
    if (!media || !crop || sameBox(media, crop)) continue;
    const key = [media.llx, media.lly, media.urx, media.ury, crop.llx, crop.lly, crop.urx, crop.ury]
      .map((v) => round1(v))
      .join("|");
    let group = groups.get(key);
    if (!group) {
      group = {
        numbers: [],
        pageWidth: round1(media.width),
        pageHeight: round1(media.height),
        visibleWidth: round1(crop.width),
        visibleHeight: round1(crop.height),
        // The backend clips the CropBox to the MediaBox (PDFBox getCropBox), so
        // these are never negative; clamp anyway so the UI never shows one.
        left: cropped(crop.llx - media.llx),
        bottom: cropped(crop.lly - media.lly),
        right: cropped(media.urx - crop.urx),
        top: cropped(media.ury - crop.ury),
      };
      groups.set(key, group);
    }
    group.numbers.push(page.number);
  }
  return [...groups.values()];
}

/** Points with at most one decimal and a Spanish decimal comma: 12.5 -> "12,5". */
export function formatPoints(value) {
  return String(round1(value)).replace(".", ",");
}
