import { linearTiming, TransitionSeries } from "@remotion/transitions";
import { fade } from "@remotion/transitions/fade";
import { CalculateMetadataFunction, Composition, useVideoConfig } from "remotion";
import { ClipScene, EndScene, ResultsScene, TitleScene } from "./Scenes";
import { cue, FADE, NARRATION, sceneFrames } from "./theme";

type Props = {};

const calculateMetadata: CalculateMetadataFunction<Props> = () => {
  const fps = 30;
  const total = NARRATION.reduce((a, _, i) => a + sceneFrames(i, fps), 0) - FADE * (NARRATION.length - 1);
  return { durationInFrames: total };
};

export const MyComposition = () => {
  return (
    <Composition
      id="ZenDemo"
      component={MyComponent}
      durationInFrames={5300}
      fps={30}
      width={1920}
      height={1080}
      calculateMetadata={calculateMetadata}
    />
  );
};

const Fade = () => <TransitionSeries.Transition presentation={fade()} timing={linearTiming({ durationInFrames: FADE })} />;

export const MyComponent: React.FC<Props> = () => {
  const { fps } = useVideoConfig();
  return (
    <TransitionSeries>
      <TransitionSeries.Sequence name="Title" durationInFrames={sceneFrames(0, fps)}>
        <TitleScene />
      </TransitionSeries.Sequence>
      {Fade()}
      <TransitionSeries.Sequence name="Detection" durationInFrames={sceneFrames(1, fps)}>
        <ClipScene
          n={2}
          kicker="Chrome extension · detection"
          title="Found on the device, before anything leaves"
          callouts={[
            { at: cue(2, "server"), text: "No server, no network" },
            { at: cue(2, "Luhn"), text: "Luhn for cards, Verhoeff for Aadhaar" },
            { at: cue(2, "structure"), text: "Password, OTP and CVV fields found by structure" },
          ]}
        />
      </TransitionSeries.Sequence>
      {Fade()}
      <TransitionSeries.Sequence name="Agent Shield" durationInFrames={sceneFrames(2, fps)}>
        <ClipScene
          n={3}
          kicker="Agent Shield"
          title="The agent sees placeholders, not data"
          callouts={[
            { at: cue(3, "Without"), text: "Without Zen: every value is readable" },
            { at: cue(3, "switches"), text: "Shield turns on when automation is detected" },
            { at: cue(3, "placeholder"), text: "Screenshot, page text and input values all redacted" },
          ]}
        />
      </TransitionSeries.Sequence>
      {Fade()}
      <TransitionSeries.Sequence name="Any page" durationInFrames={sceneFrames(3, fps)}>
        <ClipScene
          n={4}
          kicker="Any page · any agent"
          title="No integration with the agent needed"
          callouts={[
            { at: cue(4, "API"), text: "API keys and IP addresses" },
            { at: cue(4, "Phone"), text: "Phones and emails in a support chat" },
            { at: cue(4, "OTPs"), text: "OTPs, Aadhaar and PAN at sign-in" },
            { at: cue(4, "covered"), text: "New content covered in ~3 ms" },
          ]}
        />
      </TransitionSeries.Sequence>
      {Fade()}
      <TransitionSeries.Sequence name="Send guard" durationInFrames={sceneFrames(4, fps)}>
        <ClipScene
          n={5}
          kicker="AI-chat send guard"
          title="An unsafe message is stopped before it is sent"
          callouts={[
            { at: cue(5, "pauses"), text: "Card, phone and email detected locally" },
            { at: cue(5, "sanitized"), text: "“Send sanitized” is the default" },
            { at: cue(5, "editor"), text: "Fails closed if the editor refuses" },
          ]}
        />
      </TransitionSeries.Sequence>
      {Fade()}
      <TransitionSeries.Sequence name="Agent loop" durationInFrames={sceneFrames(5, fps)}>
        <ClipScene
          n={6}
          kicker="Python agent · local executor"
          title="Hijack attempts are rejected on the device"
          callouts={[
            { at: cue(6, "sees"), text: "The planner sees sanitized views only" },
            { at: cue(6, "executor"), text: "5 of 5 injection attempts rejected" },
            { at: cue(6, "risky"), text: "Irreversible click waits for approval" },
            { at: cue(6, "panel"), text: "See exactly what would leave the device" },
          ]}
        />
      </TransitionSeries.Sequence>
      {Fade()}
      <TransitionSeries.Sequence name="Results" durationInFrames={sceneFrames(6, fps)}>
        <ResultsScene />
      </TransitionSeries.Sequence>
      {Fade()}
      <TransitionSeries.Sequence name="Close" durationInFrames={sceneFrames(7, fps)}>
        <EndScene />
      </TransitionSeries.Sequence>
    </TransitionSeries>
  );
};
