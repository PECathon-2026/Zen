import { linearTiming, TransitionSeries } from "@remotion/transitions";
import { fade } from "@remotion/transitions/fade";
import { CalculateMetadataFunction, Composition, useVideoConfig } from "remotion";
import { ClipScene, EndScene, ResultsScene, TitleScene } from "./Scenes";
import { FADE, NARRATION, sceneFrames } from "./theme";

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
            { at: 2.5, text: "No server, no network" },
            { at: 7.0, text: "Luhn for cards, Verhoeff for Aadhaar" },
            { at: 12.5, text: "Password, OTP and CVV fields found by structure" },
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
            { at: 2.0, text: "Without Zen: every value is readable" },
            { at: 7.4, text: "Shield turns on when automation is detected" },
            { at: 15.0, text: "Screenshot, page text and input values all redacted" },
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
            { at: 3.5, text: "API keys, tokens, IP addresses" },
            { at: 8.0, text: "Phones and emails in a support chat" },
            { at: 13.2, text: "OTP, Aadhaar and PAN at sign-in" },
            { at: 16.5, text: "New content covered in ~3 ms" },
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
            { at: 4.0, text: "Card, phone and email detected locally" },
            { at: 12.0, text: "“Send sanitized” is the default" },
            { at: 18.0, text: "Fails closed if the editor refuses" },
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
            { at: 4.5, text: "The planner sees sanitized views only" },
            { at: 12.5, text: "5 of 5 injection attempts rejected" },
            { at: 16.0, text: "Irreversible click waits for approval" },
            { at: 19.5, text: "Every payload passes a fail-closed gate" },
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
