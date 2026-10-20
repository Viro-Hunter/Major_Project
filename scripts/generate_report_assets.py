#!/usr/bin/env python3
"""Week 11 — generate every figure and table the report needs from the working system.

    python evaluation/run_benchmark.py          # first (produces evaluation/results/benchmark.json)
    python scripts/generate_report_assets.py    # then this

Writes to docs/report_assets/:
    fig1_pipeline.png               system pipeline diagram
    fig2_insider_evidence.png       evidence subgraph of the highest-risk labelled insider
    fig3_benign_evidence.png        same view for a benign user, for contrast
    fig4_detection_comparison.png   full system vs ablation vs naive baseline
    fig5_threshold_sweep.png        precision / recall / F1 vs risk threshold
and docs/report_tables.md (captioned tables), and prints the "Proposed System" paragraph
from docs/ARCHITECTURE.md.  Numbers come only from benchmark.json, never typed by hand.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "report_assets"
BENCH = ROOT / "evaluation" / "results" / "benchmark.json"
REPORT_MD = ROOT / "evaluation" / "results" / "benchmark_report.md"

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import networkx as nx  # noqa: E402

TYPE_COLOR = {"User": "#1d4ed8", "Host": "#64748b", "FileResource": "#b45309", "Device": "#7c3aed",
              "EmailEvent": "#0e7490", "NetworkConnection": "#15803d", "AttackTechnique": "#b91c1c"}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})


def fig_pipeline(path: Path) -> None:
    stages = ["CERT r4.2\nlogs", "Ingestion &\nnormalisation", "Knowledge\ngraph + ATT&CK", "Router &\nretriever",
              "LLM verdict\n(cited edges)", "Groundedness\nself-check", "Confidence\npropagation", "Dashboard"]
    fig, ax = plt.subplots(figsize=(13, 2.4))
    ax.axis("off")
    w, gap = 1.45, 0.25
    for i, s in enumerate(stages):
        x = i * (w + gap)
        core = s.startswith("Groundedness")
        ax.add_patch(plt.Rectangle((x, 0), w, 1, fc="#fee2e2" if core else "#f1f5f9", ec="#b91c1c" if core else "#334155", lw=1.6 if core else 1))
        ax.text(x + w / 2, 0.5, s, ha="center", va="center", fontsize=8.5, fontweight="bold" if core else "normal")
        if i < len(stages) - 1:
            ax.annotate("", xy=(x + w + gap, 0.5), xytext=(x + w, 0.5), arrowprops=dict(arrowstyle="->", color="#334155"))
    ax.annotate("regenerate ≤ 2× if a cited edge is missing", xy=(4 * (w + gap) + w / 2, 1.0), xytext=(5 * (w + gap) + w / 2, 1.0),
                arrowprops=dict(arrowstyle="->", color="#b91c1c", connectionstyle="arc3,rad=0.5"), ha="center", va="bottom", fontsize=8, color="#b91c1c")
    ax.set_xlim(-0.1, len(stages) * (w + gap))
    ax.set_ylim(-0.2, 1.6)
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)


def _evidence_figure(store, user: str, verdict: dict, title: str, path: Path) -> None:
    g = nx.DiGraph()
    g.add_node(user, type="User")
    for p in verdict.get("evidence_paths", [])[:12]:
        for a, b, rel in zip(p["nodes"], p["nodes"][1:], p["relations"]):
            g.add_node(b, type=store.graph.nodes[b].get("type", ""))
            g.add_edge(a, b, rel=rel, conf=p["confidence"])
    fig, ax = plt.subplots(figsize=(9, 6.5))
    if g.number_of_edges() == 0:
        ax.text(0.5, 0.5, f"{user}: no ATT&CK evidence paths", ha="center", va="center")
        ax.axis("off")
    else:
        layers = {n: 0 if n == user else 2 if d.get("type") == "AttackTechnique" else 1 for n, d in g.nodes(data=True)}
        nx.set_node_attributes(g, layers, "layer")
        pos = nx.multipartite_layout(g, subset_key="layer", align="horizontal", scale=2)
        pos = {n: (x, -y) for n, (x, y) in pos.items()}
        colors = [TYPE_COLOR.get(g.nodes[n].get("type"), "#94a3b8") for n in g]
        nx.draw_networkx_edges(g, pos, ax=ax, width=[0.8 + 3 * g.edges[e]["conf"] for e in g.edges], edge_color="#94a3b8",
                               arrows=True, arrowsize=12, connectionstyle="arc3,rad=0.05")
        nx.draw_networkx_nodes(g, pos, ax=ax, node_color=colors, node_size=[900 if n == user else 420 for n in g])
        def short(n: str) -> str:
            kind, _, rest = n.partition(":")
            rest = rest.strip("{}")
            return {"email": f"email {rest[:12]}", "device": f"usb {rest[:12]}", "attack": rest}.get(kind, rest[:18]) if rest else n
        labels = {n: short(n) for n in g}
        nx.draw_networkx_labels(g, pos, labels, ax=ax, font_size=7, verticalalignment="bottom",
                                bbox=dict(fc="white", ec="none", alpha=0.75, pad=0.5))
        handles = [plt.Line2D([], [], marker="o", ls="", color=c, label=t) for t, c in TYPE_COLOR.items()
                   if any(g.nodes[n].get("type") == t for n in g)]
        ax.legend(handles=handles, loc="upper left", bbox_to_anchor=(1.0, 1.0), fontsize=8, frameon=False)
        ax.axis("off")
    ax.set_title(title, fontsize=10)
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig_evidence(bench: dict) -> tuple[str, str]:
    """Rebuild the benchmark's labelled graph (same seed) and draw one insider and one benign user."""
    os.environ["CYBERGRAPHRAG_OFFLINE"] = "1"
    from evaluation.scenarios import build_labelled_set
    from scripts.build_graph_from_cert import build_graph_from_rows
    from api.routes.incidents import run_checked_verdict, peer_prevalence  # noqa: F401  (pipeline tail)
    from reasoning.confidence_scoring import attach_confidence
    from reasoning.evidence import technique_prevalence
    from reasoning.groundedness_checker import check_groundedness
    from reasoning.verdict_generator import CONTEXT_KEY, generate_verdict

    cfg = bench["config"]
    ls = build_labelled_set(cfg["mode"], cfg["users"], cfg["insiders"], cfg["rows_per_user"], cfg["seed"])
    store = build_graph_from_rows(ls.rows_by_log)
    prev = technique_prevalence(store.graph)

    def verdict_for(u):
        sg = store.get_subgraph_dict(u, hops=1)
        sg[CONTEXT_KEY] = {"focus": u, "prevalence": prev}
        v = check_groundedness(generate_verdict(sg, "insider?"), sg)
        return attach_confidence(v, sg, u)

    per_user = {u: verdict_for(u) for u in ls.labels}
    insiders = [u for u, y in ls.labels.items() if y]
    benign = [u for u, y in ls.labels.items() if not y]
    top = max(insiders, key=lambda u: per_user[u]["risk_score"])
    # a benign user with evidence, closest to the median benign risk
    cand = sorted((u for u in benign if per_user[u].get("evidence_paths")), key=lambda u: per_user[u]["risk_score"])
    ben = cand[len(cand) // 2] if cand else benign[0]
    v1, v2 = per_user[top], per_user[ben]
    _evidence_figure(store, top, v1, f"Labelled insider {top} (scenario {ls.scenario_of.get(top)}): risk {v1['risk_score']:.2f}, "
                                     f"confidence {v1['confidence_pct']:.0f}%, {v1['groundedness']['status']}", OUT / "fig2_insider_evidence.png")
    _evidence_figure(store, ben, v2, f"Benign user {ben}: risk {v2['risk_score']:.2f}, confidence {v2['confidence_pct']:.0f}%",
                     OUT / "fig3_benign_evidence.png")
    return top, ben


def fig_detection(bench: dict, path: Path) -> None:
    variants = [("Full system", bench["detection"]), ("No peer baseline", bench["detection_ablation_no_peer_baseline"]),
                ("Naive: any ATT&CK match", bench["detection_naive_any_technique"])]
    metrics = ["precision", "recall", "f1", "fpr"]
    fig, ax = plt.subplots(figsize=(8, 3.8))
    width = 0.26
    for i, (name, d) in enumerate(variants):
        xs = [j + (i - 1) * width for j in range(len(metrics))]
        bars = ax.bar(xs, [d[m] for m in metrics], width, label=name, color=["#1d4ed8", "#93c5fd", "#cbd5e1"][i])
        ax.bar_label(bars, fmt="%.2f", fontsize=7, padding=2)
    ax.set_xticks(range(len(metrics)), ["Precision", "Recall", "F1", "False-positive rate"])
    ax.set_ylim(0, 1.12)
    ax.legend(frameon=False, fontsize=8, ncols=3, loc="upper center")
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)


def fig_sweep(bench: dict, path: Path) -> None:
    s = bench["threshold_sweep"]
    t = [x["threshold"] for x in s]
    fig, ax = plt.subplots(figsize=(6.5, 3.6))
    for key, label, style in (("precision", "Precision", "-o"), ("recall", "Recall", "-s"), ("f1", "F1", "-^"), ("fpr", "FPR", "--x")):
        ax.plot(t, [x[key] for x in s], style, label=label, ms=4)
    ax.axvline(bench["detection_threshold"], color="#94a3b8", lw=1)
    ax.text(bench["detection_threshold"], 1.02, " operating point", fontsize=8, color="#475569")
    ax.set_xlabel("Risk threshold")
    ax.set_ylim(0, 1.08)
    ax.legend(frameon=False, fontsize=8)
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)


CAPTIONS = {
    "Table 1": "Table I: Headline evaluation metrics (Objective 5)",
    "Table 2": "Table II: Detection effectiveness — full system, ablation without peer-prevalence discount, and naive baseline",
    "Table 3": "Table III: Precision/recall trade-off across risk thresholds",
    "Table 4": "Table IV: Detection by insider scenario",
    "Table 5": "Table V: Evidence retrieval and threat-correlation quality",
    "Table 6": "Table VI: Response time per pipeline phase",
    "Table 7": "Table VII: Groundedness self-check under simulated LLM hallucination",
}


def report_tables(path: Path) -> None:
    md = REPORT_MD.read_text()
    out = ["# Report tables", "", f"_Generated from `{REPORT_MD.relative_to(ROOT)}` by `scripts/generate_report_assets.py`._", ""]
    for block in re.split(r"(?m)^## ", md)[1:]:
        head, _, body = block.partition("\n")
        m = re.match(r"(Table \d+)", head)
        if m:
            out += [f"**{CAPTIONS.get(m.group(1), head)}**", "", body.strip(), ""]
        elif head.startswith(("Setup", "Threats")):
            out += [f"### {head}", "", body.strip(), ""]
    path.write_text("\n".join(out))


def main() -> int:
    if not BENCH.exists():
        print("evaluation/results/benchmark.json not found — run `python evaluation/run_benchmark.py` first.")
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    bench = json.loads(BENCH.read_text())
    fig_pipeline(OUT / "fig1_pipeline.png")
    top, ben = fig_evidence(bench)
    fig_detection(bench, OUT / "fig4_detection_comparison.png")
    fig_sweep(bench, OUT / "fig5_threshold_sweep.png")
    report_tables(ROOT / "docs" / "report_tables.md")
    arch = (ROOT / "docs" / "ARCHITECTURE.md").read_text()
    summary = arch.split("<!-- SUMMARY:START -->")[1].split("<!-- SUMMARY:END -->")[0].strip()
    print("Figures:", ", ".join(sorted(p.name for p in OUT.glob("*.png"))), f"(insider {top}, benign {ben})")
    print("Tables:  docs/report_tables.md")
    print("\n--- Proposed System (paste into the report) ---\n")
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
