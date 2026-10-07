#!/usr/bin/env python3
"""
log_analyzer.py - analyse CAN logs written by the STM32 + FatFS SD logger.

The firmware logs RAW frames (so it never needs reflashing when a payload layout
changes):   timestamp_ms,can_id,flags,dlc,data_hex
This tool reads them, reports per-ID traffic health (rate, gaps, dropouts),
decodes the signals you describe, plots them and flags anomalies.

Also reads simple per-sensor CSVs:  id,value   or   timestamp_ms,id,value

Usage:
    python log_analyzer.py --generate-sample sample_logs        # demo data
    python log_analyzer.py sample_logs/LOG00001.CSV             # traffic report only
    python log_analyzer.py sample_logs/LOG00001.CSV \\
        --signal cell_temp=0x101:0:2:le:0.1 \\
        --signal pack_mV=0x102:0:2:le:1 \\
        --signal current_A=0x103:0:2:le:0.1:s

Signal spec:  name=CAN_ID:start_byte:length_bytes:le|be:scale[:s]
              (add ':s' for signed values; physical value = raw * scale)
"""
import argparse
import csv
import math
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # save PNGs; works on machines with no display
import matplotlib.pyplot as plt


# ============================ simple sensor CSVs ============================
def parse_simple_log(path):
    """id,value  or  timestamp_ms,id,value  ->  (xs, ys, x_label, bad_lines)"""
    xs, ys = [], []
    has_ts = False
    bad_lines = 0
    with open(path, newline="") as f:
        for row in csv.reader(f):
            row = [c.strip() for c in row if c.strip() != ""]
            try:
                if len(row) == 3:
                    has_ts = True
                    xs.append(float(row[0]) / 1000.0)
                    ys.append(float(row[2]))
                elif len(row) == 2:
                    xs.append(float(len(xs)))
                    ys.append(float(row[1]))
                else:
                    raise ValueError
            except ValueError:
                if xs or ys:
                    bad_lines += 1   # bad line after data = real corruption
    return xs, ys, ("time (s)" if has_ts else "sample #"), bad_lines


# ============================ raw CAN frame logs ============================
def is_can_log(path):
    with open(path) as f:
        first = f.readline().strip().lower()
    return first.startswith("timestamp_ms,can_id")


def parse_can_log(path):
    """-> (frames, bad_lines); frames = [(t_s, can_id, flags, bytes)].
    A power cut can truncate the last line - such lines are counted and skipped."""
    frames, bad = [], 0
    with open(path) as f:
        next(f, None)  # header
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            try:
                if len(parts) != 5:
                    raise ValueError
                t = int(parts[0]) / 1000.0
                cid = int(parts[1], 16)
                flags = int(parts[2])
                dlc = int(parts[3])
                data = bytes.fromhex(parts[4])
                if not (flags & 2) and len(data) != dlc:   # RTR frames carry no data
                    raise ValueError
                frames.append((t, cid, flags, data))
            except ValueError:
                bad += 1
    return frames, bad


def traffic_report(name, frames, bad):
    print(f"\n=== {name} : {len(frames)} frames, {bad} malformed line(s) skipped ===")
    if not frames:
        return
    span = frames[-1][0] - frames[0][0]
    print(f"  duration {span:.1f} s")
    by_id = defaultdict(list)
    for t, cid, _fl, _d in frames:
        by_id[cid].append(t)
    print(f"  {'CAN ID':<12}{'frames':>8}{'rate Hz':>10}{'avg ms':>9}{'max gap ms':>12}  dropouts")
    for cid in sorted(by_id):
        ts = by_id[cid]
        rate = len(ts) / span if span > 0 else 0.0
        gaps = [(b - a) * 1000 for a, b in zip(ts, ts[1:])]
        avg = statistics.fmean(gaps) if gaps else 0.0
        mx = max(gaps) if gaps else 0.0
        med = statistics.median(gaps) if gaps else 0.0
        drops = sum(1 for g in gaps if med > 0 and g > 5 * med)
        flag = f"  <-- {drops} gap(s) > 5x normal period" if drops else ""
        print(f"  0x{cid:<10X}{len(ts):>8}{rate:>10.1f}{avg:>9.1f}{mx:>12.1f}{flag}")


def parse_signal_spec(spec):
    """name=0x101:0:2:le:0.1[:s]"""
    try:
        name, rest = spec.split("=", 1)
        f = rest.split(":")
        cid = int(f[0], 0)
        start, length = int(f[1]), int(f[2])
        endian = {"le": "little", "be": "big"}[f[3].lower()]
        scale = float(f[4]) if len(f) > 4 and f[4] != "s" else 1.0
        signed = f[-1].lower() == "s" and len(f) > 4
        if length < 1 or start < 0 or start + length > 8:
            raise ValueError
        return dict(name=name, id=cid, start=start, length=length,
                    endian=endian, scale=scale, signed=signed)
    except (ValueError, KeyError, IndexError):
        raise argparse.ArgumentTypeError(
            f"bad --signal '{spec}'  (expected name=ID:start:len:le|be:scale[:s])")


def decode_signal(frames, sig):
    xs, ys = [], []
    for t, cid, _fl, data in frames:
        if cid != sig["id"] or len(data) < sig["start"] + sig["length"]:
            continue
        raw = int.from_bytes(data[sig["start"]: sig["start"] + sig["length"]],
                             sig["endian"], signed=sig["signed"])
        xs.append(t)
        ys.append(raw * sig["scale"])
    return xs, ys


# ============================ anomaly detection =============================
def find_anomalies(xs, ys, k, vmin, vmax, half=5):
    """Hampel filter: flag a point if it deviates from the median of its
    neighbours (window of 2*half+1) by more than k robust standard deviations.
    Noise scale = the larger of the local MAD and the whole-log MAD (so a window
    that is quiet by chance doesn't cause false alarms). A floor of 2 ADC counts /
    2% of the data range also ignores quantisation noise.
    Optional hard limits (vmin/vmax) are checked as well."""
    flagged = {}
    n = len(ys)
    if n >= 2 * half + 1:
        meds, mads, resid = [], [], []
        for i in range(n):
            w = ys[max(0, i - half): i + half + 1]
            med = statistics.median(w)
            meds.append(med)
            mads.append(statistics.median(abs(v - med) for v in w) * 1.4826)
            resid.append(abs(ys[i] - med))
        global_sigma = statistics.median(resid) * 1.4826

        srt = sorted(ys)
        robust_range = srt[int(0.95 * (n - 1))] - srt[int(0.05 * (n - 1))]
        uniq = sorted(set(ys))
        resolution = min((b - a for a, b in zip(uniq, uniq[1:])), default=1.0)
        floor = max(2 * resolution, 0.02 * robust_range)

        for i in range(n):
            scale = max(mads[i], global_sigma, 1e-9)
            if resid[i] > k * scale and resid[i] > floor:
                flagged[i] = f"spike ({ys[i] - meds[i]:+.1f} vs local median)"
    for i, y in enumerate(ys):
        if vmin is not None and y < vmin:
            flagged[i] = f"below min {vmin}"
        if vmax is not None and y > vmax:
            flagged[i] = f"above max {vmax}"
    return flagged


def summarise(name, xs, ys, xl, flagged, bad_lines=0):
    print(f"\n--- {name} ---")
    if not ys:
        print("  no valid data")
        return
    print(f"  samples : {len(ys)}   (malformed lines skipped: {bad_lines})")
    print(f"  min/max : {min(ys):.2f} / {max(ys):.2f}")
    print(f"  mean/std: {statistics.fmean(ys):.2f} / {statistics.pstdev(ys):.2f}")
    if xl == "time (s)" and len(xs) > 1:
        dts = [xs[i] - xs[i - 1] for i in range(1, len(xs))]
        print(f"  avg period: {statistics.fmean(dts)*1000:.1f} ms"
              f"   worst gap: {max(dts)*1000:.1f} ms")
    print(f"  anomalies: {len(flagged)}")
    for i, why in list(flagged.items())[:10]:
        print(f"    - x={xs[i]:.2f}  value={ys[i]:.2f}  ({why})")
    if len(flagged) > 10:
        print(f"    ... and {len(flagged) - 10} more")


def plot_all(results, out_png):
    n = len(results)
    fig, axes = plt.subplots(n, 1, figsize=(10, 3 * n), squeeze=False)
    for ax, (name, xs, ys, xl, flagged) in zip(axes[:, 0], results):
        ax.plot(xs, ys, linewidth=1, label=name)
        if flagged:
            idx = list(flagged)
            ax.scatter([xs[i] for i in idx], [ys[i] for i in idx],
                       color="red", zorder=3, label=f"anomaly ({len(idx)})")
        ax.set_ylabel("value")
        ax.set_xlabel(xl)
        ax.grid(alpha=0.3)
        ax.legend(loc="upper right")
    fig.tight_layout()
    fig.savefig(out_png, dpi=130)
    print(f"\nPlot saved to {out_png}")


# ============================ demo data =====================================
def generate_sample(folder, seconds=60, period_ms=100):
    """A realistic raw-frame log in the firmware's format: cell temperature,
    pack voltage and current frames, with a few injected glitches and one
    comms dropout so the detectors have something to find."""
    out = Path(folder)
    out.mkdir(parents=True, exist_ok=True)
    random.seed(7)
    n = seconds * 1000 // period_ms
    glitch = {cid: {random.randrange(50, n - 50): random.choice([-1, 1]) for _ in range(3)}
              for cid in (0x101, 0x102, 0x103)}
    dropout = range(300, 340)  # 4 s of missing 0x102 frames

    def u16le(v):
        return int(v).to_bytes(2, "little", signed=False).hex().upper()

    def s16le(v):
        return int(v).to_bytes(2, "little", signed=True).hex().upper()

    lines = ["timestamp_ms,can_id,flags,dlc,data_hex"]
    for i in range(n):
        t = i * period_ms
        temp = 30 + 0.01 * i + random.gauss(0, 0.15)          # degC
        volt = 3700 - 0.3 * i + random.gauss(0, 4)            # mV
        curr = 80 + 20 * math.sin(i / 40) + random.gauss(0, 0.8)  # A
        for cid, val, scale, enc in ((0x101, temp, 0.1, u16le),
                                     (0x102, volt, 1.0, u16le),
                                     (0x103, curr, 0.1, s16le)):
            raw = val / scale
            if i in glitch[cid]:
                raw += glitch[cid][i] * abs(raw) * 0.4
            if cid == 0x102 and i in dropout:
                continue
            lines.append(f"{t},0x{cid:03X},0,2,{enc(raw)}")
    (out / "LOG00001.CSV").write_text("\r\n".join(lines) + "\r\n")
    print(f"Sample log written to {out}/LOG00001.CSV")
    print("Try:\n  python log_analyzer.py {0}/LOG00001.CSV "
          "--signal cell_temp=0x101:0:2:le:0.1 "
          "--signal pack_mV=0x102:0:2:le:1 "
          "--signal current_A=0x103:0:2:le:0.1:s".format(out))


# ============================ main ==========================================
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="log files or a folder of .CSV logs")
    ap.add_argument("--signal", action="append", default=[], type=parse_signal_spec,
                    help="signal to decode: name=ID:start:len:le|be:scale[:s] (repeatable)")
    ap.add_argument("--k", type=float, default=5.0,
                    help="spike threshold in robust std-devs (default 5)")
    ap.add_argument("--min", type=float, dest="vmin", help="hard lower limit")
    ap.add_argument("--max", type=float, dest="vmax", help="hard upper limit")
    ap.add_argument("--out", default="log_plot.png", help="output PNG name")
    ap.add_argument("--generate-sample", metavar="DIR", help="write a demo log to DIR and exit")
    args = ap.parse_args()

    if args.generate_sample:
        generate_sample(args.generate_sample)
        return

    files = []
    for p in args.paths:
        p = Path(p)
        files += sorted(list(p.glob("*.CSV")) + list(p.glob("*.csv"))) if p.is_dir() else [p]
    if not files:
        ap.error("no log files given (try --generate-sample sample_logs first)")

    results = []
    for f in files:
        if is_can_log(f):
            frames, bad = parse_can_log(f)
            traffic_report(f.name, frames, bad)
            if not args.signal:
                print("\n  (add --signal specs to decode and plot values - see --help)")
            for sig in args.signal:
                xs, ys = decode_signal(frames, sig)
                flagged = find_anomalies(xs, ys, args.k, args.vmin, args.vmax)
                label = f"{sig['name']} [0x{sig['id']:X}]"
                summarise(label, xs, ys, "time (s)", flagged)
                if ys:
                    results.append((label, xs, ys, "time (s)", flagged))
        else:
            xs, ys, xl, bad = parse_simple_log(f)
            flagged = find_anomalies(xs, ys, args.k, args.vmin, args.vmax)
            summarise(f.name, xs, ys, xl, flagged, bad)
            if ys:
                results.append((f.name, xs, ys, xl, flagged))
    if results:
        plot_all(results, args.out)


if __name__ == "__main__":
    sys.exit(main())
