import { Audio, Video } from "@remotion/media";
import { AbsoluteFill, Easing, interpolate, spring, staticFile, useCurrentFrame, useVideoConfig } from "remotion";
import { C, cue, F, NARRATION, WORDS, type Word } from "./theme";

const ease = Easing.bezier(0.16, 1, 0.3, 1);

// Fades and lifts its children in at `at` seconds.
const Reveal: React.FC<{ at: number; children: React.ReactNode; style?: React.CSSProperties }> = ({ at, children, style }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  return (
    <div
      style={{
        ...style,
        opacity: interpolate(frame, [at * fps, at * fps + 0.6 * fps], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: ease }),
        translate: interpolate(frame, [at * fps, at * fps + 0.6 * fps], ["0px 24px", "0px 0px"], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: ease }),
      }}
    >
      {children}
    </div>
  );
};

const Kicker: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div style={{ font: `500 22px ${F.mono}`, color: C.muted, letterSpacing: 4, textTransform: "uppercase" }}>{children}</div>
);

const Chip: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <span style={{ background: C.chip, color: C.bg, font: `600 26px ${F.mono}`, padding: "6px 16px", borderRadius: 8 }}>{children}</span>
);

const Backdrop: React.FC = () => (
  <AbsoluteFill style={{ background: `radial-gradient(1200px 700px at 85% 15%, #2a1d16 0%, ${C.bg} 60%)` }} />
);


// Group narration words into short caption lines: break after punctuation once a line has 3+ words, or at 7 words.
const pagesOf = (words: Word[]) => {
  const pages: Word[][] = [[]];
  for (const w of words) {
    const cur = pages[pages.length - 1];
    cur.push(w);
    if (cur.length >= 7 || (cur.length >= 3 && /[.,:;?!]$/.test(w.text))) pages.push([]);
  }
  return pages.filter((p) => p.length);
};

// Burned-in captions for narration clip n, current word highlighted.
const Captions: React.FC<{ n: number }> = ({ n }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const t = (frame / fps) * 1000;
  const pages = pagesOf(WORDS[n - 1]);
  const i = pages.findIndex((p, k) => t >= p[0].startMs && (k === pages.length - 1 ? t <= p[p.length - 1].endMs + 600 : t < pages[k + 1][0].startMs));
  if (i < 0) return null;
  return (
    <div style={{ position: "absolute", left: 0, right: 0, bottom: 52, display: "flex", justifyContent: "center" }}>
      <div style={{ background: "rgba(10,9,7,.82)", borderRadius: 14, padding: "12px 28px", maxWidth: 1500, font: `500 40px/1.35 ${F.body}`, textAlign: "center" }}>
        {pages[i].map((w, k) => (
          <span key={k} style={{ color: t >= w.startMs ? C.text : C.dim }}>{(k ? " " : "") + w.text}</span>
        ))}
      </div>
    </div>
  );
};

export const TitleScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const pop = spring({ frame, fps, config: { damping: 200 } });
  return (
    <AbsoluteFill style={{ padding: "0 140px", justifyContent: "center", fontFamily: F.body, color: C.text }}>
      <Backdrop />
      <Audio src={staticFile("audio/n1.mp3")} />
      <Captions n={1} />
      <div style={{ position: "relative" }}>
        <Reveal at={0.1}><Kicker>PECathon 2026 · PS-004 PrivacyLens</Kicker></Reveal>
        <div style={{ font: `600 230px/1 ${F.head}`, letterSpacing: -6, margin: "24px 0 10px", scale: interpolate(pop, [0, 1], [0.92, 1]), opacity: pop }}>
          Zen<span style={{ color: C.accent }}>.</span>
        </div>
        <Reveal at={0.7}><div style={{ fontSize: 52 }}>A local privacy lens for AI browser agents</div></Reveal>
        <Reveal at={cue(1, "work")}>
          <div style={{ font: `italic 400 50px/1.3 ${F.head}`, color: C.accent, marginTop: 40, maxWidth: 1400 }}>
            “Compute what is sensitive locally. Reason globally only on sanitized data.”
          </div>
        </Reveal>
        <div style={{ display: "flex", gap: 22, marginTop: 56 }}>
          <Reveal at={cue(1, "card")}><Chip>[REDACTED:CARD]</Chip></Reveal>
          <Reveal at={cue(1, "Aadhaar")}><Chip>[REDACTED:AADHAAR]</Chip></Reveal>
          <Reveal at={cue(1, "passwords")}><Chip>[REDACTED:PASSWORD]</Chip></Reveal>
          <Reveal at={cue(1, "OTPs")}><Chip>[REDACTED:OTP]</Chip></Reveal>
        </div>
      </div>
    </AbsoluteFill>
  );
};

type Callout = { at: number; text: string };

// A recorded browser clip in a window frame, with a text column that builds up in sync with the narration.
export const ClipScene: React.FC<{ n: number; kicker: string; title: string; callouts: Callout[] }> = ({ n, kicker, title, callouts }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const len = (NARRATION[n - 1] + 0.6) * fps;
  return (
    <AbsoluteFill style={{ fontFamily: F.body, color: C.text }}>
      <Backdrop />
      <Audio src={staticFile(`audio/n${n}.mp3`)} />
      <Captions n={n} />
      <div style={{ position: "absolute", left: 100, top: 130, width: 520 }}>
        <Reveal at={0}><Kicker>{kicker}</Kicker></Reveal>
        <Reveal at={0.25}><div style={{ font: `600 62px/1.1 ${F.head}`, margin: "22px 0 48px" }}>{title}</div></Reveal>
        {callouts.map((c) => (
          <Reveal key={c.text} at={c.at} style={{ display: "flex", gap: 18, alignItems: "baseline", marginBottom: 30 }}>
            <span style={{ width: 14, height: 14, borderRadius: 7, background: C.accent, flex: "none", translate: "0px -4px" }} />
            <span style={{ fontSize: 34, lineHeight: 1.3, color: C.text }}>{c.text}</span>
          </Reveal>
        ))}
      </div>
      <div
        style={{
          position: "absolute", left: 680, top: 160, width: 1160, borderRadius: 18, overflow: "hidden",
          border: `1px solid ${C.border}`, background: C.surface, boxShadow: "0 30px 80px rgba(0,0,0,.45)",
          opacity: interpolate(frame, [0, 0.5 * fps], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
          scale: interpolate(frame, [0, len], [0.985, 1.02], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
        }}
      >
        <div style={{ height: 44, display: "flex", alignItems: "center", gap: 10, padding: "0 18px", borderBottom: `1px solid ${C.border}` }}>
          {["#ff5f57", "#febc2e", "#28c840"].map((c) => <span key={c} style={{ width: 13, height: 13, borderRadius: 7, background: c }} />)}
          <span style={{ marginLeft: 18, font: `18px ${F.mono}`, color: C.dim }}>Chromium · Zen extension loaded · synthetic data</span>
        </div>
        <Video src={staticFile(`clips/s${n}.mp4`)} muted style={{ width: 1160, height: 652.5, display: "block" }} />
      </div>
    </AbsoluteFill>
  );
};

const Stat: React.FC<{ at: number; value: string; label: string }> = ({ at, value, label }) => (
  <Reveal at={at} style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 20, padding: "30px 34px" }}>
    <div style={{ font: `600 76px/1.05 ${F.head}`, color: C.accent }}>{value}</div>
    <div style={{ fontSize: 28, color: C.muted, marginTop: 12, lineHeight: 1.35 }}>{label}</div>
  </Reveal>
);

export const ResultsScene: React.FC = () => (
  <AbsoluteFill style={{ padding: "110px 120px", fontFamily: F.body, color: C.text }}>
    <Backdrop />
    <Audio src={staticFile("audio/n7.mp3")} />
      <Captions n={7} />
    <div style={{ position: "relative" }}>
      <Reveal at={0}><Kicker>Measured · reproducible · synthetic data</Kicker></Reveal>
      <Reveal at={0.2}><div style={{ font: `600 78px ${F.head}`, margin: "18px 0 50px" }}>What leaves the page</div></Reveal>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 30 }}>
        <Stat at={cue(7, "OCR")} value="21 → 0" label="of 34 sensitive values readable by OCR in agent screenshots" />
        <Stat at={cue(7, "Zero")} value="0 · 0" label="values left in page text and input values, shield on" />
        <Stat at={cue(7, "useful")} value="100%" label="of non-sensitive context still readable" />
        <Stat at={cue(7, "ninety")} value="0.99" label="text detector recall, 150 labelled cases" />
        <Stat at={cue(7, "hundred")} value="1.00" label="text detector precision" />
        <Stat at={cue(7, "fifty")} value="263" label="Python tests pass, plus JS ↔ Python parity" />
      </div>
      <Reveal at={cue(7, "fifty") + 0.5}><div style={{ font: `22px ${F.mono}`, color: C.dim, marginTop: 40 }}>eval.shield_eval · eval.run_eval · pytest — claims cover the tested synthetic pages and pathways only</div></Reveal>
    </div>
  </AbsoluteFill>
);

export const EndScene: React.FC = () => (
  <AbsoluteFill style={{ padding: "0 140px", justifyContent: "center", fontFamily: F.body, color: C.text }}>
    <Backdrop />
    <Audio src={staticFile("audio/n8.mp3")} />
      <Captions n={8} />
    <div style={{ position: "relative" }}>
      <Reveal at={0}><Kicker>Known gaps</Kicker></Reveal>
      <Reveal at={cue(8, "tricky")}><div style={{ fontSize: 38, color: C.muted, margin: "20px 0 70px", maxWidth: 1500, lineHeight: 1.4 }}>
        Obfuscated PII (spaced digits, “at / dot” emails) · person names need NER · faces the detector misses
      </div></Reveal>
      <Reveal at={cue(8, "Zen")}><div style={{ font: `600 170px/1 ${F.head}`, letterSpacing: -4 }}>Zen<span style={{ color: C.accent }}>.</span></div></Reveal>
      <Reveal at={cue(8, "agents")}><div style={{ fontSize: 50, marginTop: 20 }}>AI agents that see what they need, and nothing more.</div></Reveal>
      <Reveal at={cue(8, "nothing")}><div style={{ font: `26px ${F.mono}`, color: C.dim, marginTop: 40 }}>github.com/PECathon-2026/Zen</div></Reveal>
    </div>
  </AbsoluteFill>
);
