from .detect import Span, detect


def redact(text: str) -> tuple[str, list[Span]]:
    """Replace each detected span with [REDACTED:KIND]. Originals are not kept in the output."""
    spans = detect(text)
    out, pos = [], 0
    for s in spans:
        out += [text[pos:s.start], f"[REDACTED:{s.kind}]"]
        pos = s.end
    out.append(text[pos:])
    return "".join(out), spans
