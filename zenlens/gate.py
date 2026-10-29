from .detect import detect


class Blocked(Exception):
    pass


def egress_check(payload: str, canaries: tuple[str, ...] = ()) -> str:
    """Last gate before any external call. Fail-closed: any hit or any error blocks."""
    try:
        hits = detect(payload)
        leaked = [c for c in canaries if c and c in payload]
    except Exception as e:  # scanner broke -> do not send
        raise Blocked(f"scanner error: {e!r}") from e
    if hits or leaked:
        kinds = sorted({h.kind for h in hits} | ({"CANARY"} if leaked else set()))
        raise Blocked(f"blocked, detected: {', '.join(kinds)}")
    return payload
