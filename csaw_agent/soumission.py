"""Assemblage du dossier de soumission CSAW 2026 à partir des essais.

Chaque essai (« run » GitHub Actions) laisse un dossier `runs/` : un `bilan.json`
et, par challenge, une trace chaînée `trace.jsonl` et son `rapport.md`. Ce module
lit plusieurs de ces dossiers et produit la partie déterministe de la soumission :

    transcripts/{categorie}_{nom}_{solved|unsolved}.jsonl   trace intacte (preuve)
    transcripts/{categorie}_{nom}_{solved|unsolved}.md      rapport lisible tiré de la trace
    ancillary/essais.md, ancillary/essais.json             toutes les tentatives
    ancillary/traces/<essai>/<challenge>.jsonl             trace de chaque tentative

Règles : pour chaque challenge, la tentative retenue est la dernière réussie,
sinon la dernière tentée (les essais sont donnés dans l'ordre chronologique).
Chaque trace est revérifiée (chaîne SHA-256) et copiée octet pour octet ; une
trace dont la chaîne est rompue n'est jamais publiée. Aucun LLM n'intervient.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from .trace import verify_trace


@dataclass
class Attempt:
    essai: str          # nom du dossier de l'essai (l'ID du run GitHub)
    id: str             # p. ex. 2026q-rev-autobahn
    category: str       # crypto, forensics, misc, pwn, rev, web
    status: str
    model: str | None
    llm_steps: int | None
    trace: Path | None  # None si le challenge n'a laissé aucune trace
    approche: str = "autonome"  # ou "hybride" (indice humain consigné dans la trace)

    @property
    def name(self) -> str:
        """Nom court du challenge : `2026q-rev-autobahn` → `autobahn`."""
        parts = self.id.split("-", 2)
        return parts[2] if len(parts) == 3 and parts[0].startswith("20") else self.id

    @property
    def solved(self) -> bool:
        return self.status == "resolu"

    def transcript_stem(self) -> str:
        return f"{self.category}_{self.name}_{'solved' if self.solved else 'unsolved'}"


def _locate(essai_dir: Path, run_dir: str | None) -> Path | None:
    """Retrouve le dossier d'un challenge dans l'artefact téléchargé.

    `bilan.json` note `runs/<challenge>/<horodatage>` ; l'artefact contient le
    contenu de `runs/`, donc on essaie le chemin tel quel puis sans son premier
    élément. On refuse tout chemin qui sortirait du dossier de l'essai.
    """
    if not run_dir:
        return None
    rel = Path(run_dir)
    if rel.is_absolute():
        rel = Path(*rel.parts[1:])
    base = essai_dir.resolve()
    for candidate in (rel, Path(*rel.parts[1:]) if len(rel.parts) > 1 else None):
        if candidate is None:
            continue
        path = (essai_dir / candidate).resolve()
        if base in path.parents and (path / "trace.jsonl").is_file():
            return path / "trace.jsonl"
    return None


def _trouver_bilan(essai_dir: Path) -> Path | None:
    """bilan.json à la racine de l'artefact, ou dans un sous-dossier (artefact à
    plusieurs chemins, p. ex. runs/ + atelier/) : on prend le moins profond."""
    direct = essai_dir / "bilan.json"
    if direct.is_file():
        return direct
    candidats = sorted(essai_dir.glob("*/bilan.json"), key=lambda p: len(p.parts))
    return candidats[0] if candidats else None


def read_attempts(essai_dir: Path) -> list[Attempt]:
    bilan = _trouver_bilan(essai_dir)
    if bilan is None:
        return []
    # Le nom de l'essai (étiquette) reste l'ID du run ; les traces se cherchent à
    # côté du bilan (racine de l'artefact, ou sous-dossier si l'artefact est nesté).
    essai_nom = essai_dir.name
    trace_base = bilan.parent
    attempts = []
    for entry in json.loads(bilan.read_text(encoding="utf-8")):
        if entry.get("status") == "ignore_serveur":
            continue
        attempts.append(Attempt(
            essai=essai_nom,
            id=entry.get("id", "?"),
            category=entry.get("category_db") or "misc",
            status=entry.get("status", "?"),
            model=entry.get("model"),
            llm_steps=entry.get("llm_steps"),
            trace=_locate(trace_base, entry.get("run_dir")),
            # Les essais antérieurs à l'option indice n'ont pas le champ : autonomes.
            approche=entry.get("approche", "autonome"),
        ))
    return attempts


def choose(attempts: list[Attempt]) -> dict[str, Attempt]:
    """Tentative retenue par challenge : la dernière réussie, sinon la dernière."""
    chosen: dict[str, Attempt] = {}
    for a in attempts:
        if a.trace is None:
            continue
        current = chosen.get(a.id)
        if current is None or a.solved or not current.solved:
            chosen[a.id] = a
    return chosen


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assemble(essai_dirs: list[Path], out: Path) -> dict:
    """Écrit transcripts/ et ancillary/ dans `out`. Retourne un résumé."""
    out = Path(out)
    transcripts = out / "transcripts"
    ancillary = out / "ancillary"
    transcripts.mkdir(parents=True, exist_ok=True)
    (ancillary / "traces").mkdir(parents=True, exist_ok=True)

    attempts: list[Attempt] = []
    for d in essai_dirs:
        attempts.extend(read_attempts(Path(d)))

    rows, rejected = [], []
    for a in attempts:
        row = {"essai": a.essai, "id": a.id, "categorie": a.category, "statut": a.status,
               "modele": a.model, "etapes_llm": a.llm_steps, "trace_sha256": None,
               "approche": a.approche,
               "trace_integre": None}
        if a.trace is not None:
            ok, message = verify_trace(a.trace)
            row["trace_integre"] = ok
            row["trace_sha256"] = _sha256(a.trace)
            if ok:
                dest = ancillary / "traces" / a.essai / f"{a.id}.jsonl"
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(a.trace, dest)
            else:
                rejected.append(f"{a.essai}/{a.id} : {message}")
        rows.append(row)

    intact = {(r["essai"], r["id"]) for r in rows if r["trace_integre"]}
    chosen = choose([a for a in attempts if (a.essai, a.id) in intact])
    for a in chosen.values():
        stem = a.transcript_stem()
        shutil.copyfile(a.trace, transcripts / f"{stem}.jsonl")
        report = a.trace.with_name("rapport.md")
        if report.is_file():
            shutil.copyfile(report, transcripts / f"{stem}.md")

    (ancillary / "essais.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    (ancillary / "essais.md").write_text(_essais_md(rows, chosen), encoding="utf-8")

    solved = sorted(a.id for a in chosen.values() if a.solved)
    return {"challenges": len(chosen), "resolus": solved,
            "tentatives": len(rows), "traces_rejetees": rejected}


def _essais_md(rows: list[dict], chosen: dict[str, Attempt]) -> str:
    kept = {(a.essai, a.id) for a in chosen.values()}
    solved = sorted({r["id"] for r in rows if r["statut"] == "resolu"})
    lines = [
        "# Toutes les tentatives",
        "",
        "Tableau généré automatiquement à partir des `bilan.json` de chaque essai "
        "(un essai = un lancement GitHub Actions, désigné par son identifiant). "
        "La colonne « Retenue » marque la tentative publiée dans `transcripts/`. "
        "Chaque trace est vérifiable : `python -m csaw_agent verify-trace <trace.jsonl>`.",
        "",
        f"Challenges résolus : **{len(solved)}** ({', '.join(solved) or 'aucun'}).",
        "",
        "| Essai | Challenge | Catégorie | Statut | Approche | Modèle | Étapes LLM | Trace intègre | Retenue |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        model = (r["modele"] or "—").split("@")[0]
        integre = {True: "oui", False: "NON", None: "pas de trace"}[r["trace_integre"]]
        retenue = "✔" if (r["essai"], r["id"]) in kept else ""
        lines.append(f"| {r['essai']} | {r['id']} | {r['categorie']} | {r['statut']} | "
                     f"{r.get('approche', 'autonome')} | {model} | {r['etapes_llm'] if r['etapes_llm'] is not None else '—'} | "
                     f"{integre} | {retenue} |")
    return "\n".join(lines) + "\n"
