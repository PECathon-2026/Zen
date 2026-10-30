import { loadFont } from "@remotion/fonts";
import { staticFile } from "remotion";

loadFont({ family: "Fraunces", url: staticFile("fonts/fraunces-latin-wght-normal.woff2"), weight: "100 900" });
loadFont({ family: "Fraunces", url: staticFile("fonts/fraunces-latin-wght-italic.woff2"), weight: "100 900", style: "italic" });
loadFont({ family: "Public Sans", url: staticFile("fonts/public-sans-latin-wght-normal.woff2"), weight: "100 900" });
loadFont({ family: "JetBrains Mono", url: staticFile("fonts/jetbrains-mono-latin-wght-normal.woff2"), weight: "100 800" });

// Zen web-app dark palette (app/static/app.css).
export const C = {
  bg: "#16140f",
  surface: "#211e19",
  border: "#5a4a40",
  text: "#f3f1ec",
  muted: "#d9b8ab",
  dim: "#a68d80",
  accent: "#ffb59f",
  chip: "#e4e2de",
};
export const F = {
  head: "Fraunces, Georgia, serif",
  body: "'Public Sans', system-ui, sans-serif",
  mono: "'JetBrains Mono', Menlo, monospace",
};

// Narration clip lengths in seconds (ffprobe of public/audio/n1..n8.mp3).
export const NARRATION = [18.504, 22.824, 24.312, 20.016, 22.752, 24.216, 24.96, 13.512];
export const FADE = 12; // frames of crossfade between scenes
// Scene length: narration + 0.6 s breath + the frames the next crossfade overlaps.
export const sceneFrames = (i: number, fps: number) => Math.ceil((NARRATION[i] + 0.6) * fps) + FADE;
