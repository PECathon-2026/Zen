import { loadFont } from "@remotion/fonts";
import { staticFile } from "remotion";
import captionData from "./captions.json";

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
export const NARRATION = [20.256, 20.112, 25.752, 18.768, 19.44, 23.232, 25.032, 11.496];

// Word timings from the TTS engine, one array per narration clip.
export type Word = { text: string; startMs: number; endMs: number };
export const WORDS: Word[][] = captionData;

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
// Seconds at which `word` is first spoken in clip n (1-based); throws so a typo cannot silently mistime a reveal.
export const cue = (n: number, word: string) => {
  const w = WORDS[n - 1].find((x) => norm(x.text).startsWith(norm(word)));
  if (!w) throw new Error(`cue "${word}" not found in narration ${n}`);
  return w.startMs / 1000;
};
export const FADE = 12; // frames of crossfade between scenes
// Scene length: narration + 0.6 s breath + the frames the next crossfade overlaps.
export const sceneFrames = (i: number, fps: number) => Math.ceil((NARRATION[i] + 0.6) * fps) + FADE;
