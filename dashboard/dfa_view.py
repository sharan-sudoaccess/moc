"""Graphviz (DOT) rendering of the part of the DFA that a run actually visited.

The graph is built ONLY from the trace returned by the API, so every node and
edge drawn is a real state / a real δ application from that run. It is a
projection of the full automaton (which has hundreds of states), not a
separate teaching model.
"""

from __future__ import annotations

from collections import OrderedDict

EDGE_STYLE = {
    "trie": 'color="#38BDF8" fontcolor="#38BDF8" penwidth=1.6',
    "failure": 'color="#F59E42" fontcolor="#F59E42" style=dashed penwidth=1.4',
    "reset": 'color="#56627A" fontcolor="#8592A6" style=dotted',
    "skip": 'color="#56627A" fontcolor="#8592A6" style=dashed',
}


def _esc(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _short(label: str, limit: int = 26) -> str:
    return label if len(label) <= limit else "…" + label[-(limit - 1):]


def trace_to_dot(trace: list[dict], *, include_resets: bool = True) -> str:
    nodes: "OrderedDict[int, dict]" = OrderedDict()
    nodes[0] = {"label": "ε", "accepting": False, "outputs": set()}
    edges: "OrderedDict[tuple[int, int, str], list[str]]" = OrderedDict()

    for step in trace:
        src, dst, kind = step["from_state"], step["to_state"], step["transition"]
        node = nodes.setdefault(dst, {"label": step["to_label"], "accepting": step["accepting"], "outputs": set()})
        node["outputs"].update(step["outputs"])
        if kind == "reset" and not include_resets:
            continue
        edges.setdefault((src, dst, kind), []).append(f'{step["step"]}:{step["token"]}')

    lines = [
        "digraph DFA {",
        '  graph [rankdir=LR bgcolor="transparent" pad=0.3 nodesep=0.35 ranksep=0.5 fontname="Helvetica"];',
        '  node [shape=box style="rounded,filled" fontname="Helvetica" fontsize=10 color="#3A465A" '
        'fontcolor="#D7DEE8" fillcolor="#161E2B" margin="0.12,0.06"];',
        '  edge [fontname="Helvetica" fontsize=9 arrowsize=0.6];',
        '  start [shape=point width=0.08 color="#8592A6"];',
        '  start -> q0 [color="#8592A6"];',
    ]
    for q, info in nodes.items():
        label = f"q{q}\\n{_esc(_short(info['label']))}"
        if info["outputs"]:
            label += "\\n⇒ " + _esc(", ".join(sorted(info["outputs"])))
        attrs = [f'label="{label}"']
        if info["accepting"]:
            attrs += ['peripheries=2', 'color="#F0506E"', 'fillcolor="#2A1520"', 'penwidth=1.4']
        if q == 0:
            attrs += ['color="#38BDF8"']
        lines.append(f"  q{q} [{' '.join(attrs)}];")
    for (src, dst, kind), steps in edges.items():
        shown = steps if len(steps) <= 3 else steps[:2] + [f"+{len(steps) - 2} more"]
        label = "\\n".join(_esc(s) for s in shown)
        lines.append(f'  q{src} -> q{dst} [label="{label}" {EDGE_STYLE[kind]}];')
    lines.append("}")
    return "\n".join(lines)
