# Agent CTF autonome — CSAW LLM CTF Attack Competition 2026

Travail pratique du cours 8IAR805 « Cybersécurité et intelligence artificielle » (UQAC).
L'agent reçoit un challenge CTF, l'analyse et cherche le flag sans aucune intervention humaine.
Il vérifie ensuite ce flag et laisse une trace complète de ses actions.

## Architecture

Construction « par retrait » (chapitre 4) : tout ce que du code fait de façon exacte (lire des octets,
décoder, calculer, vérifier le flag) est confié à des outils déterministes. Le LLM ne garde que ce
qu'aucun outil ne sait faire : identifier le type de challenge, choisir la stratégie, l'adapter après
un échec.

| Module | Étape du pipeline | Rôle |
| --- | --- | --- |
| `csaw_agent/challenge.py` | 1. Ingestion | Lit le `.json`, copie les fichiers en lecture seule, met le flag de côté |
| `csaw_agent/flag.py` | 6. Vérification | Compare au flag attendu et ne renvoie qu'un booléen ; repère les candidats |
| `csaw_agent/trace.py` | 7. Trace | Journal JSONL en ajout seul, chaîné par SHA-256, vérifiable |
| `csaw_agent/untrusted.py` | Sécurité | Nettoie, tronque et encadre les données non fiables avant le LLM |
| `csaw_agent/llm.py` | Modèle | Interface unique `complete(messages)` pour tout service compatible OpenAI |
| `csaw_agent/tools.py` | 4. Outils | Outils typés et validés : `file_info`, `read_file`, `strings`, `decode`, `xor_bruteforce` |
| `csaw_agent/agent.py` | 2-5. Type, stratégie, adaptation | Boucle : le LLM choisit une action en JSON, le code l'exécute |
| `csaw_agent/run.py` | Orchestration | Un dossier par run, pré-scan sans LLM, puis boucle LLM si besoin |
| `csaw_agent/report.py` | 7. Rapport | `rapport.md` tiré de la trace par du code : flag validé, intégrité, déroulement |

Dans la boucle, toute chaîne qui ressemble à un flag dans une sortie d'outil est vérifiée
automatiquement. Les erreurs (réponse illisible, outil mal appelé, flag faux) sont renvoyées au LLM
pour qu'il change de stratégie, dans la limite d'un budget d'actions (`--max-steps`).

## Choisir le modèle (0 $)

Tous les services ci-dessous parlent le même protocole ; seul l'argument `--model` change.

| Où | Commande |
| --- | --- |
| Ollama en local (développement, petit modèle) | `--model ollama:qwen2.5:3b` |
| Ollama sur un GPU gratuit (Kaggle, Colab) | notebook clé en main : [docs/essai-gpu-gratuit.md](docs/essai-gpu-gratuit.md) |
| Modèle servi par vLLM ailleurs | `--model <modèle> --base-url https://<serveur>/v1` |
| Offre gratuite d'une API | `--model groq:<modèle>` ou `--model openrouter:<modèle>`, clé dans `CSAW_API_KEY` |

La clé d'API n'est lue que dans la variable d'environnement et n'est jamais écrite dans la trace.

## Utilisation

```bash
python -m csaw_agent run tests/fixtures/demo-clair/challenge.json          # pré-scan seul
python -m csaw_agent run tests/fixtures/demo-encode/challenge.json --model ollama:qwen2.5:3b
python -m csaw_agent run-all tests/fixtures --model ollama:qwen2.5:7b         # tous les challenges, bilan.json
python -m csaw_agent verify-trace runs/demo-clair/<horodatage>/trace.jsonl
python -m csaw_agent report runs/demo-clair/<horodatage>/trace.jsonl
python -m pytest
```

Chaque run produit `runs/<challenge>/<horodatage>/` avec `trace.jsonl`, `rapport.md` et une copie
des fichiers. Le rapport cite l'empreinte finale de la chaîne de hachages de la trace : on peut
vérifier que la trace jointe est bien celle dont il est tiré.

## Règles respectées

- Le flag attendu n'est jamais transmis au LLM, qui ne reçoit que le résultat vrai/faux de `check_flag`.
- La description, les fichiers et les sorties d'outils sont encadrés comme données non fiables ;
  les outils refusent tout fichier hors de l'espace de travail du run.
- La trace est écrite par le code, jamais retouchée ; `verify-trace` détecte toute modification.
- Les prompts ne contiennent aucune solution ni write-up.
- Les challenges de `tests/fixtures/` ont été créés pour ce projet et ne viennent d'aucune compétition.

## Documentation

Document de conception : https://claude.ai/artifact/6SttWmKq4MwDtjhUHTHtpj
