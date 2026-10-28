# Agent CTF autonome — CSAW LLM CTF Attack Competition 2026

Travail pratique du cours 8IAR805 « Cybersécurité et intelligence artificielle » (UQAC).
L'agent reçoit un challenge CTF, l'analyse et cherche le flag sans aucune intervention humaine.
Il vérifie ensuite ce flag et laisse une trace complète de ses actions.

## État actuel : le socle

Le socle couvre les parties du pipeline qui n'ont pas besoin de LLM. Elles sont confiées à du code
déterministe, conformément au principe de construction « par retrait » du chapitre 4.

| Module | Étape du pipeline | Rôle |
| --- | --- | --- |
| `csaw_agent/challenge.py` | 1. Ingestion | Lit le `.json`, copie les fichiers en lecture seule, met le flag de côté |
| `csaw_agent/flag.py` | 6. Vérification | Compare au flag attendu et ne renvoie qu'un booléen ; repère les candidats |
| `csaw_agent/trace.py` | 7. Trace | Journal JSONL en ajout seul, chaîné par SHA-256, vérifiable |
| `csaw_agent/untrusted.py` | Sécurité | Nettoie, tronque et encadre les données non fiables avant le LLM |
| `csaw_agent/run.py` | Orchestration | Un dossier par run, pré-scan déterministe, résumé final |

La boucle LLM (identification du type, stratégie, outils, adaptation) se branchera dans `run.py`,
entre le pré-scan et la fin du run.

## Utilisation

```bash
python -m csaw_agent run tests/fixtures/demo-clair/challenge.json
python -m csaw_agent verify-trace runs/demo-clair/<horodatage>/trace.jsonl
python -m pytest
```

Chaque run produit `runs/<challenge>/<horodatage>/` avec `trace.jsonl` et une copie des fichiers.

## Règles respectées

- Le flag attendu n'est jamais transmis au LLM, qui ne reçoit que le résultat vrai/faux de `check_flag`.
- La trace est écrite par le code, jamais retouchée ; `verify-trace` détecte toute modification.
- Les prompts ne contiennent aucune solution ni write-up.
- Les challenges de `tests/fixtures/` ont été créés pour ce projet et ne viennent d'aucune compétition.

## Documentation

Document de conception : https://claude.ai/artifact/6SttWmKq4MwDtjhUHTHtpj
