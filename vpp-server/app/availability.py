from . import crypto_service, revocation

SLOT_MINUTES = 30
SLOTS_PER_DAY = 24 * 60 // SLOT_MINUTES
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


class InvalidAvailability(Exception):
    """The declared calendar is malformed."""


def validate(slots: dict) -> dict:
    """Check the declared calendar and return it normalised."""
    if not isinstance(slots, dict):
        raise InvalidAvailability("availability must be an object keyed by weekday")

    missing = [d for d in DAYS if d not in slots]
    if missing:
        raise InvalidAvailability(f"missing weekday(s): {', '.join(missing)}")
    unknown = [d for d in slots if d not in DAYS]
    if unknown:
        raise InvalidAvailability(f"unknown weekday(s): {', '.join(unknown)}")

    normalised = {}
    for day in DAYS:
        bitmap = slots[day]
        if not isinstance(bitmap, str):
            raise InvalidAvailability(f"{day}: bitmap must be a string")
        if len(bitmap) != SLOTS_PER_DAY:
            raise InvalidAvailability(
                f"{day}: expected {SLOTS_PER_DAY} slots of {SLOT_MINUTES} min, "
                f"got {len(bitmap)}"
            )
        if set(bitmap) - {"0", "1"}:
            raise InvalidAvailability(f"{day}: bitmap may only contain 0 and 1")
        normalised[day] = bitmap
    return normalised


def verify_signed(jws_token: str, expected_owner: str) -> dict:
    """Verify an owner-signed calendar and return {"slots", "version"}; the caller checks monotonicity."""
    try:
        owner_cert, issuer, payload = crypto_service.verify_signer(jws_token)
    except ValueError as e:
        raise InvalidAvailability(f"calendar signer {e}")
    # Same subject as the channel is not the same certificate: a superseded one keeps the name.
    if revocation.is_revoked(owner_cert, issuer):
        raise InvalidAvailability("calendar signer certificate is revoked")
    if owner_cert.subject.rfc4514_string() != expected_owner:
        raise InvalidAvailability("calendar not signed by the appliance's owner")

    version = payload.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
        raise InvalidAvailability("calendar must carry a positive integer version")
    return {"slots": validate(payload.get("slots")), "version": version}


def slot_index(hour: int, minute: int = 0) -> int:
    """Slot covering a wall-clock time, e.g. 15:30 -> 31 with 30-min slots."""
    return (hour * 60 + minute) // SLOT_MINUTES


def slot_label(index: int) -> str:
    minutes = index * SLOT_MINUTES
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def is_available(slots: dict, day: str, start: int, end: int) -> bool:
    """True if the appliance is available for EVERY slot in [start, end)."""
    bitmap = slots.get(day, "")
    if start < 0 or end > SLOTS_PER_DAY or start >= end:
        return False
    return all(c == "1" for c in bitmap[start:end])


def empty_week() -> dict:
    return {day: "0" * SLOTS_PER_DAY for day in DAYS}
