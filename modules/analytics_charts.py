"""Matplotlib charts generated from AARC's stored data."""

import json
from collections import Counter
from datetime import datetime
from io import BytesIO
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
TELEMETRY_FILE = ROOT / "data" / "telemetry_events.json"
AUDIT_FILE = ROOT / "data" / "cloudtrail_analysis_audit.json"
BG = "#ffffff"
FG = "#222222"


def _records(path, key=None):
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            value = data.get(key, []) if key else data.get("events", [])
            return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []
    return []


def _finish(fig):
    fig.tight_layout()
    output = BytesIO()
    fig.savefig(output, format="png", dpi=110, facecolor=BG)
    plt.close(fig)
    output.seek(0)
    return output


def make_chart(chart_type):
    fig, ax = plt.subplots(figsize=(5.8, 3.0))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.tick_params(colors=FG, labelsize=8)
    ax.xaxis.label.set_color(FG)
    ax.yaxis.label.set_color(FG)
    ax.title.set_color(FG)
    for spine in ax.spines.values():
        spine.set_color("#d0d0d0")

    if chart_type == "risk":
        rows = _records(AUDIT_FILE, "records")
        counts = Counter(
            str(row.get("triage_risk", "UNKNOWN")).upper()
            for row in rows
        )
        labels = ["LOW", "MEDIUM", "HIGH"]
        values = [counts[label] for label in labels]
        total = sum(values)
        bars = ax.bar(labels, values, color=["#38b764", "#e8b547", "#e05260"])
        bar_labels = [
            f"{v} ({v / total:.1%})" if total else "0"
            for v in values
        ]
        ax.bar_label(bars, labels=bar_labels, color=FG, padding=4, fontsize=9)
        ax.set_title(f"CloudTrail Risk Distribution (N={len(rows)} audit records)")
        ax.set_xlabel("Rule-based risk classification")
        ax.set_ylabel("Unique audited events")
        ax.set_ylim(0, max(values + [1]) * 1.25)
        ax.grid(axis="y", color="#dddddd", linewidth=0.7)
        return _finish(fig)

    if chart_type == "telemetry":
        rows = _records(TELEMETRY_FILE)
        points = []
        for row in rows:
            stamp = row.get("timestamp")
            try:
                when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                cpu = float(row["cpu_usage_pct"])
                memory = float(row["memory_usage_pct"])
                points.append((when, cpu, memory))
            except (AttributeError, TypeError, ValueError, KeyError):
                continue

        points = sorted(points, key=lambda point: point[0])[-60:]
        if points:
            times = [point[0] for point in points]
            ax.plot(times, [p[1] for p in points],
                    label="CPU %", marker="o", markersize=2)
            ax.plot(times, [p[2] for p in points],
                    label="Memory %", marker="o", markersize=2)
            ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
            ax.legend(facecolor=BG, labelcolor=FG)
        else:
            ax.text(0.5, 0.5, "No valid telemetry samples",
                    ha="center", color=FG, transform=ax.transAxes)
        ax.set_title(f"CPU and Memory Usage — Last {len(points)} Samples")
        if points:
            ax.text(
                0.02, 0.97,
                f"Latest sample: CPU {points[-1][1]:.1f}% | "
                f"Memory {points[-1][2]:.1f}%",
                transform=ax.transAxes,
                va="top",
                color=FG,
                bbox=dict(facecolor=BG, edgecolor="#39465b", alpha=0.95),
            )
        ax.set_ylabel("Resource usage (%)")
        ax.set_ylim(0, 100)
        ax.set_xlabel("Time (UTC)")
        ax.grid(color="#e1e1e1", linewidth=0.6)
        return _finish(fig)

    if chart_type == "events":
        rows = _records(AUDIT_FILE, "records")
        counts = Counter(
            row.get("event_name") or "Unknown" for row in rows
        ).most_common(10)
        counts.reverse()
        if counts:
            labels, values = zip(*counts)
            bars = ax.barh(labels, values, color="#42a5f5")
            bar_labels = [
                f"{v} ({v / len(rows):.1%})" if rows else str(v)
                for v in values
            ]
            ax.bar_label(bars, labels=bar_labels, color=FG, padding=4, fontsize=9)
            ax.set_xlim(0, max(values) * 1.3)
        else:
            ax.text(0.5, 0.5, "No CloudTrail events",
                    ha="center", color=FG, transform=ax.transAxes)
        ax.set_title(f"Most Frequent AWS Events (N={len(rows)} audit records)")
        ax.set_xlabel("Unique audited events (count and % of total)")
        ax.grid(axis="x", color="#e1e1e1", linewidth=0.6)
        return _finish(fig)

    plt.close(fig)
    raise ValueError("Unknown chart type")
