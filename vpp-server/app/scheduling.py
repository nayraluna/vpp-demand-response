import datetime

from . import availability as av


def _recovering(appliance: dict, now: datetime.datetime) -> int | None:
    """Minutes still to wait before this appliance may participate again."""
    last_end = appliance.get("last_activation_end")
    if last_end is None:
        return None
    if isinstance(last_end, str):
        last_end = datetime.datetime.fromisoformat(last_end)
    elapsed = (now - last_end).total_seconds() / 60
    remaining = appliance.get("recovery", 0) - elapsed
    return int(remaining) if remaining > 0 else None


def select(power_w: int, day: str, slot_start: int, slot_end: int,
           appliances: list[dict], now: datetime.datetime | None = None) -> dict:
    """Choose the appliances that will serve a requested reduction."""
    if day not in av.DAYS:
        raise ValueError(f"unknown day {day!r}")
    if not (0 <= slot_start < slot_end <= av.SLOTS_PER_DAY):
        raise ValueError("invalid slot range")
    now = now or datetime.datetime.now(datetime.timezone.utc)

    duration_min = (slot_end - slot_start) * av.SLOT_MINUTES
    eligible, rejected = [], []

    for appliance in appliances:
        slots = appliance.get("availability")
        if not slots:
            reason = "no availability declared"
        elif not av.is_available(slots, day, slot_start, slot_end):
            reason = "not available for the whole requested interval"
        elif duration_min > appliance["max_curtail"]:
            reason = (f"interval of {duration_min} min exceeds its maximum "
                      f"curtailment time ({appliance['max_curtail']} min)")
        elif (remaining := _recovering(appliance, now)) is not None:
            reason = f"still recovering ({remaining} min left)"
        else:
            eligible.append(appliance)
            continue
        rejected.append({"ven": appliance["ven_subject"], "reason": reason})

    # Fewest appliances first: take the largest contributions until covered.
    eligible.sort(key=lambda a: a["nominal_power"], reverse=True)
    selected, aggregated = [], 0
    for appliance in eligible:
        if aggregated >= power_w:
            break
        selected.append({"ven": appliance["ven_subject"],
                         "power": appliance["nominal_power"]})
        aggregated += appliance["nominal_power"]

    feasible = aggregated >= power_w
    result = {
        "feasible": feasible,
        "requested_power": power_w,
        "day": day,
        "slot_start": slot_start,
        "slot_end": slot_end,
        "interval": f"{av.slot_label(slot_start)}-{av.slot_label(slot_end)}",
        "duration_minutes": duration_min,
        "eligible_count": len(eligible),
        "rejected": rejected,
    }
    if feasible:
        result.update({"selected": selected, "aggregated_power": aggregated,
                       "appliance_count": len(selected)})
    else:
        # Nothing is activated: the request cannot be served.
        offered = sum(a["nominal_power"] for a in eligible)
        result.update({"selected": [], "aggregated_power": 0,
                       "appliance_count": 0, "available_power": offered,
                       "shortfall": power_w - offered,
                       "reason": "not possible: available flexibility "
                                 f"({offered} W) is below the requested {power_w} W"})
    return result
