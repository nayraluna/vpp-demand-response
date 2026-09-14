from . import availability as av

# Reference price the platform maintains, in euros per kWh.
REFERENCE_PRICE_EUR_PER_KWH = 0.15


def energy_not_consumed_kwh(nominal_power_w: int, reduction_pct: int,
                            slot_start: int, slot_end: int) -> float:
    """Energy the appliance did not consume during the curtailment.

    power actually shed (W) x duration (h) / 1000 -> kWh
    """
    hours = (slot_end - slot_start) * av.SLOT_MINUTES / 60
    shed_w = nominal_power_w * (reduction_pct / 100)
    return round(shed_w * hours / 1000, 3)


def reward_eur(energy_kwh: float,
               price: float = REFERENCE_PRICE_EUR_PER_KWH) -> float:
    return round(energy_kwh * price, 4)


def settle(participation: dict,
           price: float = REFERENCE_PRICE_EUR_PER_KWH) -> dict:
    """Add the economic figures to one verified participation."""
    energy = energy_not_consumed_kwh(
        participation["nominal_power"], participation["reduction_pct"],
        participation["slot_start"], participation["slot_end"])
    return {**participation,
            "interval": f"{av.slot_label(participation['slot_start'])}-"
                        f"{av.slot_label(participation['slot_end'])}",
            "energy_kwh": energy,
            "price_eur_per_kwh": price,
            "reward_eur": reward_eur(energy, price)}


def summarise(participations: list[dict],
              price: float = REFERENCE_PRICE_EUR_PER_KWH) -> dict:
    """What the mobile application shows the user: how much they earned."""
    settled = [settle(p, price) for p in participations]
    return {
        "participations": settled,
        "count": len(settled),
        "total_energy_kwh": round(sum(p["energy_kwh"] for p in settled), 3),
        "total_reward_eur": round(sum(p["reward_eur"] for p in settled), 4),
        "price_eur_per_kwh": price,
    }
