"""Rapport de résolution (étape 7 du pipeline).

Le rapport est produit par du code à partir de la trace, jamais par le LLM :
il ne peut donc rien affirmer que la trace ne contienne pas. Il cite
l'empreinte finale de la chaîne de hachages, ce qui permet à quiconque de
vérifier que la trace jointe est bien celle dont le rapport est tiré.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .trace import verify_trace

EXCERPT = 300


def _cell(value, limit: int = EXCERPT) -> str:
    """Rend une valeur sûre dans une cellule de tableau Markdown."""
    if value is None:
        return "—"
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = text.replace("\r", "").replace("\n", " ⏎ ")
    if len(text) > limit:
        text = text[:limit] + " […]"
    # Le contenu vient en partie du challenge : on neutralise la mise en forme.
    for ch in "\\`|*_<>[]#":
        text = text.replace(ch, "\\" + ch)
    return text or "—"


def build_report(trace_path: Path) -> str:
    trace_path = Path(trace_path)
    ok, integrity = verify_trace(trace_path)
    raw = trace_path.read_bytes()
    events = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]

    def first(kind):
        return next((e["payload"] for e in events if e["type"] == kind), {})

    view, end = first("ingestion"), (events[-1]["payload"] if events and
                                     events[-1]["type"] == "end" else {})
    checks = [e["payload"] for e in events if e["type"] == "check_flag"]
    valid = next((c for c in checks if c["valid"]), None)
    stops = [e["payload"] for e in events if e["type"] == "decision" and "stop" in e["payload"]]

    lines = [
        f"# Rapport de résolution : {_cell(view.get('name', '?'))}",
        "",
        "Rapport généré automatiquement à partir de la trace, sans intervention humaine ni LLM.",
        "",
        "## Résultat",
        "",
        "| | |",
        "| --- | --- |",
        f"| Statut | {_cell(end.get('status', 'inconnu (run interrompu)'))} |",
        f"| Flag | {_cell(valid['candidate']) if valid else 'non trouvé'} |",
        f"| Validé par `check_flag` | {'oui, source : ' + _cell(valid['source']) if valid else 'non'} |",
        f"| Catégorie annoncée | {_cell(view.get('category'))} |",
        f"| Catégorie identifiée par l'agent | {_cell(end.get('category'))} |",
        f"| Modèle | {_cell(end.get('model') or 'aucun (pré-scan seul)')} |",
        f"| Actions du LLM | {end.get('llm_steps', 0)} |",
        f"| Vérifications de flag | {len(checks)} |",
        f"| Durée | {end.get('duration_s', '?')} s |",
        "",
        "## Intégrité de la trace",
        "",
        f"- Vérification de la chaîne : **{'intègre' if ok else 'ÉCHEC'}** ({_cell(integrity)})",
        f"- Événements : {len(events)}",
        f"- Empreinte finale de la chaîne : `{events[-1]['hash'] if events else '—'}`",
        f"- SHA-256 du fichier `trace.jsonl` : `{hashlib.sha256(raw).hexdigest()}`",
        "- Revérifier : `python -m csaw_agent verify-trace trace.jsonl`",
        "",
        "## Challenge",
        "",
        f"- Serveur : {_cell(view.get('server') or 'aucun')}",
    ]
    for f in view.get("files", []):
        lines.append(f"- Fichier {_cell(f['name'])} : {f['size']} octets, sha256 `{f['sha256']}`")

    lines += ["", "## Déroulement", "",
              "| Étape | Catégorie | Raisonnement du LLM | Action | Résultat |",
              "| --- | --- | --- | --- | --- |"]
    category, pending, answered = "", None, None  # answered : étape LLM sans action valide

    def row(cat, call, result):
        return (f"| {call['step']} | {_cell(cat)} | {_cell(call.get('pensee'))} "
                f"| {_cell(call['tool'])} {_cell(call['args'])} | {result} |")

    for e in events:
        p = e["payload"]
        if e["type"] in ("llm_response", "end") and answered is not None:
            lines.append(f"| {answered} | — | — | — | réponse illisible, renvoyée au LLM |")
            answered = None
        if e["type"] == "llm_response":
            answered = p["step"]
        if e["type"] == "tool_call":
            answered = None
        if e["type"] == "decision" and "categorie" in p:
            category = p["categorie"]
        elif e["type"] == "tool_call":
            pending = (category, p)
        elif e["type"] == "tool_result" and p.get("tool") == "prescan":
            found = ", ".join(p["candidates"]) or "aucun candidat"
            lines.append(f"| pré-scan | — | — | recherche de flag dans {_cell(p['source'])} "
                         f"| {_cell(found)} |")
        elif e["type"] == "tool_result" and pending:
            status = "ok" if p["ok"] else "erreur"
            lines.append(row(*pending, f"{status} : {_cell(p['output'], 160)}"))
            pending = None
        elif e["type"] == "check_flag" and pending and p["source"] == "llm":
            lines.append(row(*pending, "flag valide" if p["valid"] else "flag refusé"))
            pending = None
        elif e["type"] in ("prompt", "llm_response", "decision", "end") and pending:
            # Action sans sortie d'outil : abandon, ou appel mal formé renvoyé au LLM.
            lines.append(row(*pending, "abandon" if pending[1]["tool"] == "give_up"
                             else "appel refusé, renvoyé au LLM"))
            pending = None

    lines += ["", "## Vérifications du flag", ""]
    if checks:
        lines += ["| Candidat | Source | Valide |", "| --- | --- | --- |"]
        lines += [f"| {_cell(c['candidate'])} | {_cell(c['source'])} | "
                  f"{'oui' if c['valid'] else 'non'} |" for c in checks]
    else:
        lines.append("Aucun candidat vérifié.")

    if stops:
        lines += ["", "## Arrêt", ""]
        lines += [f"- {_cell(s['stop'])}" + (f" : {_cell(s.get('reason') or s.get('error'))}"
                                             if s.get("reason") or s.get("error") else "")
                  for s in stops]
    return "\n".join(lines) + "\n"


def write_report(trace_path: Path) -> Path:
    out = Path(trace_path).with_name("rapport.md")
    out.write_text(build_report(trace_path), encoding="utf-8")
    return out
