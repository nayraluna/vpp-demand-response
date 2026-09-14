import argparse
import datetime
import json
import random
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "vpp-server"))
from app import availability as av  # noqa: E402
from app import db  # noqa: E402

SYN_PREFIX = "CN=syn-"          # marks every synthetic subject in the DB
SYN_USER_PREFIX = "CN=syn-user-"

# Appliance types: nominal power range (W, in steps of 50) and the fixed
# operational constraints max (min of curtailment) and rec (min of recovery).
TYPES = {
    "ac":       {"power": (1800, 2400), "max": 120, "rec": 30},
    "fridge":   {"power": (150, 300),   "max": 30,  "rec": 90},
    "boiler":   {"power": (1200, 2000), "max": 180, "rec": 60},
    "heatpump": {"power": (900, 1600),  "max": 90,  "rec": 45},
}

# Availability profiles: which days and which hour range the owner authorises.
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri")
WEEKEND = ("sat", "sun")
PROFILES = {
    "worker":     (WEEKDAYS, 17, 23),
    "evening":    (av.DAYS, 18, 23),
    "night":      (av.DAYS, 0, 7),
    "homeoffice": (WEEKDAYS, 9, 14),
    "weekend":    (WEEKEND, 10, 22),
}


def _bitmap(days, start_hour: int, end_hour: int) -> dict:
    week = {}
    start, end = start_hour * 2, end_hour * 2
    for day in av.DAYS:
        week[day] = ("0" * start + "1" * (end - start) +
                     "0" * (av.SLOTS_PER_DAY - end)) if day in days \
            else "0" * av.SLOTS_PER_DAY
    return week


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def clear() -> dict:
    """Remove every synthetic row; real participants are left untouched."""
    with sqlite3.connect(db.DB_FILE) as c:
        removed = {
            "availability": c.execute(
                "DELETE FROM availability WHERE ven_subject LIKE ?",
                (SYN_PREFIX + "%",)).rowcount,
            "appliances": c.execute(
                "DELETE FROM appliances WHERE ven_subject LIKE ?",
                (SYN_PREFIX + "%",)).rowcount,
            "users": c.execute(
                "DELETE FROM users WHERE subject LIKE ?",
                (SYN_USER_PREFIX + "%",)).rowcount,
        }
    return removed


def generate(users: int = 20, seed: int = 42) -> dict:
    """(Re)create a deterministic synthetic population: same seed, same fleet."""
    db.initialize()
    clear()
    rng = random.Random(seed)
    now = _now()
    n_appliances = 0
    for i in range(1, users + 1):
        owner = f"{SYN_USER_PREFIX}{i:03d}"
        db.add_user(owner, "SYNTHETIC", now)
        for k in range(rng.randint(1, 3)):
            kind = rng.choice(sorted(TYPES))
            spec = TYPES[kind]
            lo, hi = spec["power"]
            power = rng.randrange(lo, hi + 1, 50)
            profile = rng.choice(sorted(PROFILES))
            days, h0, h1 = PROFILES[profile]
            ven = f"CN=syn-{kind}-{i:03d}-{k + 1}"
            db.add_appliance(ven, owner, "SYNTHETIC", power,
                             spec["max"], spec["rec"], now)
            db.set_availability(ven, _bitmap(days, h0, h1), now)
            n_appliances += 1
    return {"users": users, "appliances": n_appliances, "seed": seed}


# ------------------------------------------------------------------ export ---
def export_doc() -> dict:
    """The synthetic population as a JSON-serialisable document."""
    with sqlite3.connect(db.DB_FILE) as c:
        rows = c.execute(
            """SELECT a.ven_subject, a.owner, a.nominal_power, a.max_curtail,
                      a.recovery, v.slots
               FROM appliances a LEFT JOIN availability v
                 ON v.ven_subject = a.ven_subject
               WHERE a.ven_subject LIKE ?
               ORDER BY a.owner, a.ven_subject""",
            (SYN_PREFIX + "%",)).fetchall()
    users: dict[str, list] = {}
    for ven, owner, power, max_c, rec, slots in rows:
        users.setdefault(owner, []).append({
            "ven": ven, "nominal_power": power, "max_curtail": max_c,
            "recovery": rec,
            "availability": json.loads(slots) if slots else None,
        })
    return {
        "kind": "tfg-synthetic-population",
        "exported_at": _now(),
        "users": [{"subject": s, "appliances": a} for s, a in sorted(users.items())],
    }


def import_doc(doc: dict) -> dict:
    """Replace the current synthetic population with the one in the document."""
    if doc.get("kind") != "tfg-synthetic-population":
        raise ValueError("not a tfg-synthetic-population document")
    db.initialize()
    clear()
    now = _now()
    n_users = n_appliances = 0
    for user in doc["users"]:
        db.add_user(user["subject"], "SYNTHETIC", now)
        n_users += 1
        for a in user["appliances"]:
            db.add_appliance(a["ven"], user["subject"], "SYNTHETIC",
                             a["nominal_power"], a["max_curtail"], a["recovery"], now)
            if a.get("availability"):
                db.set_availability(a["ven"], a["availability"], now)
            n_appliances += 1
    return {"users": n_users, "appliances": n_appliances}


# ------------------------------------------------------------------- views ---
def view_appliances() -> str:
    """View 1: every appliance's declared power and operational parameters."""
    with sqlite3.connect(db.DB_FILE) as c:
        rows = c.execute(
            """SELECT a.ven_subject, a.owner, a.nominal_power, a.max_curtail,
                      a.recovery, v.slots
               FROM appliances a LEFT JOIN availability v
                 ON v.ven_subject = a.ven_subject
               ORDER BY a.ven_subject""").fetchall()
    lines = [f"{'appliance':<42} {'owner':<24} {'P (W)':>6} {'max':>5} "
             f"{'rec':>5} {'slots/week':>10}  origin",
             "-" * 104]
    total_power = 0
    for ven, owner, power, max_c, rec, slots in rows:
        declared = sum(b.count("1") for b in json.loads(slots).values()) if slots else 0
        origin = "synthetic" if ven.startswith(SYN_PREFIX) else "REAL"
        total_power += power
        lines.append(f"{ven:<42} {owner:<24} {power:>6} {max_c:>5} "
                     f"{rec:>5} {declared:>10}  {origin}")
    lines.append("-" * 104)
    lines.append(f"{len(rows)} appliances, {total_power} W nominal in total")
    return "\n".join(lines)


def aggregate_data(day: str) -> list[dict]:
    """View 2 data: available power and appliance count per slot of one day."""
    if day not in av.DAYS:
        raise ValueError(f"unknown day {day!r}")
    fleet = db.list_appliances_for_selection()
    out = []
    for slot in range(av.SLOTS_PER_DAY):
        available = [a for a in fleet
                     if a["availability"]
                     and a["availability"].get(day, "")[slot] == "1"]
        out.append({"slot": slot, "label": av.slot_label(slot),
                    "power_w": sum(a["nominal_power"] for a in available),
                    "count": len(available)})
    return out


def view_aggregate(day: str) -> str:
    """View 2: aggregated availability per time slot, as a bar chart."""
    data = aggregate_data(day)
    peak = max((d["power_w"] for d in data), default=0)
    lines = [f"aggregated available power per slot - {day} "
             f"(peak {peak / 1000:.1f} kW)", "-" * 72]
    for d in data:
        bar = "#" * (round(d["power_w"] / peak * 40) if peak else 0)
        lines.append(f"{d['label']}  {d['power_w'] / 1000:>6.1f} kW "
                     f"({d['count']:>2})  {bar}")
    return "\n".join(lines)


# --------------------------------------------------------------------- cli ---
def main() -> None:
    parser = argparse.ArgumentParser(description="Backoffice - synthetic population for the aggregation demo.")
    sub = parser.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="create a deterministic synthetic population")
    g.add_argument("--users", type=int, default=20)
    g.add_argument("--seed", type=int, default=42)
    sub.add_parser("appliances", help="view 1: parameters of every appliance")
    a = sub.add_parser("aggregate", help="view 2: available power per time slot")
    a.add_argument("--day", default="mon", choices=av.DAYS)
    e = sub.add_parser("export", help="write the population to a JSON file")
    e.add_argument("--file", default="population.json")
    i = sub.add_parser("import", help="load a population from a JSON file")
    i.add_argument("--file", default="population.json")
    sub.add_parser("clear", help="remove every synthetic row")

    args = parser.parse_args()
    db.initialize()
    if args.command == "generate":
        r = generate(args.users, args.seed)
        print(f"generated {r['users']} users with {r['appliances']} appliances "
              f"(seed {r['seed']})")
    elif args.command == "appliances":
        print(view_appliances())
    elif args.command == "aggregate":
        print(view_aggregate(args.day))
    elif args.command == "export":
        doc = export_doc()
        Path(args.file).write_text(json.dumps(doc, indent=2))
        n = sum(len(u["appliances"]) for u in doc["users"])
        print(f"exported {len(doc['users'])} users / {n} appliances to {args.file}")
    elif args.command == "import":
        r = import_doc(json.loads(Path(args.file).read_text()))
        print(f"imported {r['users']} users with {r['appliances']} appliances")
    elif args.command == "clear":
        r = clear()
        print(f"removed {r['users']} users, {r['appliances']} appliances, "
              f"{r['availability']} calendars")


if __name__ == "__main__":
    main()
