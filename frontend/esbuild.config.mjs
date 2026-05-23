/**
 * Build-Skript für das Fathometer-Frontend.
 * Baut CSS via lightningcss, JS via esbuild, kopiert Fonts, schreibt Asset-Manifest.
 */

import * as esbuild from "esbuild";
import { transform, Features } from "lightningcss";
import { createHash } from "node:crypto";
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  copyFileSync,
  readdirSync,
  rmSync,
  existsSync,
} from "node:fs";
import { resolve, dirname, join, basename } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const isWatch = process.argv.includes("--watch");

// Pfade
const SRC_CSS = resolve(__dirname, "src/css/app.css");
const SRC_JS_VENDOR = resolve(__dirname, "src/js/vendor.js");
const SRC_JS_APP = resolve(__dirname, "src/js/app.js");
const SRC_FONTS = resolve(__dirname, "src/fonts");

const DIST_BASE = resolve(__dirname, "../app/static/dist");
const DIST_CSS = join(DIST_BASE, "css");
const DIST_JS = join(DIST_BASE, "js");
const DIST_FONTS = join(DIST_BASE, "fonts");
const MANIFEST_PATH = join(DIST_BASE, "manifest.json");

// Verzeichnisse sicherstellen
[DIST_CSS, DIST_JS, DIST_FONTS].forEach((d) => mkdirSync(d, { recursive: true }));

/**
 * 8-Zeichen SHA-256-Hash des Dateiinhalts.
 */
function contentHash(content) {
  return createHash("sha256").update(content).digest("hex").slice(0, 8);
}

/**
 * Entfernt alle gehashten CSS/JS-Dateien in einem Verzeichnis
 * (Muster: name.<8hex>.{css,js}).
 */
function cleanHashedFiles(dir, ext) {
  if (!existsSync(dir)) return;
  readdirSync(dir)
    .filter((f) => /\.[0-9a-f]{8}\.(css|js)$/.test(f))
    .forEach((f) => {
      try {
        rmSync(join(dir, f));
      } catch (_) {
        // Ignorieren wenn Datei bereits weg
      }
    });
}

/**
 * CSS-Build: lightningcss liest app.css (mit @import-Auflösung), minifiziert,
 * ergänzt Autoprefixer-Targets, schreibt gehashte Output-Datei.
 * Gibt den Manifest-Key zurück: { "css/app.css": "css/app.<hash>.css" }
 */
async function buildCSS() {
  cleanHashedFiles(DIST_CSS, "css");

  const inputCode = readFileSync(SRC_CSS);

  let { code } = transform({
    filename: SRC_CSS,
    code: inputCode,
    minify: true,
    sourceMap: false,
    drafts: { nesting: true },
    targets: {
      // Autoprefixer-Äquivalent: deckt moderne Browser ab (Chrome 100+, Firefox 100+, Safari 15+)
      chrome: 100 << 16,
      firefox: 100 << 16,
      safari: (15 << 16) | (1 << 8),
    },
    include: Features.Nesting,
  });

  const hash = contentHash(code);
  const outFilename = `app.${hash}.css`;
  const outPath = join(DIST_CSS, outFilename);
  writeFileSync(outPath, code);
  console.log(`CSS  → dist/css/${outFilename} (${(code.length / 1024).toFixed(1)} KB)`);
  return { "css/app.css": `css/${outFilename}` };
}

/**
 * JS-Build: esbuild bundled vendor.js und app.js als IIFE.
 * Gibt die Manifest-Einträge zurück.
 */
async function buildJS() {
  cleanHashedFiles(DIST_JS, "js");

  const entries = [
    { key: "js/vendor.js", entryPoint: SRC_JS_VENDOR, name: "vendor" },
    { key: "js/app.js", entryPoint: SRC_JS_APP, name: "app" },
  ];

  const manifest = {};

  for (const { key, entryPoint, name } of entries) {
    // Erst ohne Hash bauen um den Inhalt zu erhalten
    const result = await esbuild.build({
      entryPoints: [entryPoint],
      bundle: true,
      format: "iife",
      minify: true,
      sourcemap: false,
      write: false,
      logLevel: "silent",
    });

    const code = result.outputFiles[0].contents;
    const hash = contentHash(code);
    const outFilename = `${name}.${hash}.js`;
    const outPath = join(DIST_JS, outFilename);
    writeFileSync(outPath, code);
    console.log(`JS   → dist/js/${outFilename} (${(code.length / 1024).toFixed(1)} KB)`);
    manifest[key] = `js/${outFilename}`;
  }

  return manifest;
}

/**
 * Font-Kopie: alle woff2-Dateien aus src/fonts nach dist/fonts.
 * Fonts werden NICHT gehashed (Pfade in tokens.css referenzieren sie direkt).
 */
function copyFonts() {
  const fonts = readdirSync(SRC_FONTS).filter((f) => f.endsWith(".woff2"));
  for (const font of fonts) {
    const src = join(SRC_FONTS, font);
    const dest = join(DIST_FONTS, font);
    copyFileSync(src, dest);
    console.log(`Font → dist/fonts/${font}`);
  }
}

/**
 * Schreibt das Asset-Manifest als JSON.
 */
function writeManifest(manifest) {
  writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2));
  console.log("Manifest → dist/manifest.json");
  console.log(JSON.stringify(manifest, null, 2));
}

/**
 * Einmaliger Build-Lauf.
 */
async function build() {
  console.log("=== Fathometer Frontend Build ===");
  const [cssManifest, jsManifest] = await Promise.all([buildCSS(), buildJS()]);
  copyFonts();
  writeManifest({ ...cssManifest, ...jsManifest });
  console.log("=== Build abgeschlossen ===");
}

if (isWatch) {
  // Watch-Modus: einmaliger Build + esbuild-Context für JS-Watch.
  // CSS-Watch ist nicht Teil von esbuild — erneuter Build bei Änderung
  // über nodemon o.ä. oder manuelles Re-Trigger. Pragmatische Phase-A-Lösung.
  console.log("Watch-Modus: initialer Build, dann JS-Watch via esbuild.");
  await build();

  // JS-Watch-Context (esbuild watch-Fähigkeit)
  const vendorCtx = await esbuild.context({
    entryPoints: [SRC_JS_VENDOR],
    bundle: true,
    format: "iife",
    minify: false,
    sourcemap: "inline",
    outdir: DIST_JS,
    logLevel: "info",
  });
  const appCtx = await esbuild.context({
    entryPoints: [SRC_JS_APP],
    bundle: true,
    format: "iife",
    minify: false,
    sourcemap: "inline",
    outdir: DIST_JS,
    logLevel: "info",
  });
  await Promise.all([vendorCtx.watch(), appCtx.watch()]);
} else {
  await build();
}
