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
| `csaw_agent/tools.py` | 4. Outils | Outils typés et validés : `file_info`, `read_file`, `strings`, `decode`, `xor_bruteforce`, `extract`, `shell` (option `--shell`) |
| `csaw_agent/sandbox.py` | Sécurité | Bac à sable du shell : utilisateur sans privilèges, sans réseau, base de challenges illisible (vérifié au démarrage) |
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
| Offre gratuite d'une API | `--model gemini:gemini-3.8-flash`, ou `openrouter:`, `groq:`, `cerebras:`, `deepseek:` |
| Routage multi-modèles par catégorie | `--models "crypto=openrouter:deepseek/deepseek-r1:free,default=gemini:gemini-3.8-flash"` |

La clé de chaque fournisseur est lue dans `<FOURNISSEUR>_API_KEY` (p. ex. `GEMINI_API_KEY`,
`OPENROUTER_API_KEY`), avec repli sur `CSAW_API_KEY` ; jamais écrite dans la trace.

## Utilisation

```bash
python -m csaw_agent run tests/fixtures/demo-clair/challenge.json          # pré-scan seul
python -m csaw_agent run tests/fixtures/demo-encode/challenge.json --model ollama:qwen2.5:3b
python -m csaw_agent run-all tests/fixtures --model ollama:qwen2.5:7b         # tous les challenges, bilan.json
python -m csaw_agent run-all CSAW26_LLMAC_DB/dataset.json --skip-server --model ollama:qwen2.5:7b
python -m csaw_agent verify-trace runs/demo-clair/<horodatage>/trace.jsonl
python -m csaw_agent report runs/demo-clair/<horodatage>/trace.jsonl
python -m pytest
```

Chaque run produit `runs/<challenge>/<horodatage>/` avec `trace.jsonl`, `rapport.md` et une copie
des fichiers. Le rapport cite l'empreinte finale de la chaîne de hachages de la trace : on peut
vérifier que la trace jointe est bien celle dont il est tiré.

## Cascade frugale pilotée par la progression

`--cascade "preset:modele_gratuit>preset:modele_fort"` fait travailler d'abord un modèle
gratuit. À chaque étape, le code mesure la progression : gain d'information (lignes de
sortie jamais vues, notes, hypothèses tranchées) ou échec (erreur d'outil, action répétée,
flag refusé, réponse illisible). Quand l'agent stagne (`--patience` étapes sans gain, ou
3 échecs d'affilée), ou si le modèle tombe en erreur, **c'est le code qui décide** de passer
au palier suivant. Le modèle plus fort ne relit pas l'historique : il reçoit un état compact
établi par le code (notes, hypothèses, actions déjà faites, candidats refusés).
Chaque escalade et sa raison sont consignées dans la trace et dans `rapport.md`.

```bash
python -m csaw_agent run-all CSAW26_LLMAC_DB/dataset.json --shell \
  --cascade "openrouter:nvidia/nemotron-3.5-super-vl:free>openrouter:moonshotai/kimi-k3.1-pro"
python -m csaw_agent cascade-traces runs/**/trace.jsonl   # évaluation à coût nul sur des traces
```

## Agent forgeron (bibliothèque d'outils)

Avec `--atelier DOSSIER`, l'agent peut **garder un script qu'il a écrit** et le **réutiliser
sur les challenges suivants**. Quand il écrit un outil utile avec `write_file`, il le range avec
l'action `garder_outil` ; le **code** vérifie qu'il compile, l'étiquette (catégorie, challenge
d'origine) et le range dans une bibliothèque qui survit d'un challenge à l'autre. Sur un challenge
suivant, les outils disponibles sont listés dans le prompt de départ, et l'action `utiliser_outil`
en copie un dans l'espace de travail, prêt à être lancé par `shell`.

```bash
python -m csaw_agent run-all CSAW26_LLMAC_DB/dataset.json --shell --atelier atelier --model ...
```

Chaque conservation et chaque réutilisation sont des **décisions tracées** : on vérifie dans la
trace chaînée quand un outil est né et quand il a resservi. C'est la démarche « par retrait »
appliquée à la mémoire outillée : le modèle écrit la logique une fois, le code en fait un outil
fiable et persistant.

Pour la catégorie **pwn**, le shell du bac à sable dispose d'un débogueur (`gdb`) et de la
bibliothèque `pwntools`, en plus du désassembleur (`objdump`) et de l'outil réseau borné au seul
serveur du challenge.

## Approche hybride (indice humain)

Le règlement CSAW autorise, challenge par challenge, une approche hybride agent + humain, tant
que la solution vient de l'IA. L'option `--indice` (ou `--indices fichier.json` pour `run-all`,
input `indices` du workflow) ajoute un indice humain au prompt de départ :

```bash
python -m csaw_agent run chemin/challenge.json --model ... --indice "le fichier semble encodé"
python -m csaw_agent run-all CSAW26_LLMAC_DB/dataset.json --model ... --indices indices.json
```

- L'indice est **consigné mot pour mot dans la trace chaînée, avant le premier appel au modèle** :
  impossible de l'ajouter ou de le retoucher après coup sans que `verify-trace` le détecte.
- Le code **refuse tout indice contenant une chaîne au format d'un flag** (et les indices vides
  ou de plus de 500 caractères) : l'humain oriente, il ne donne jamais la réponse.
- `rapport.md` et le récapitulatif de soumission affichent l'approche (`autonome` / `hybride`)
  et l'indice exact.

## Règles respectées

- Le flag attendu n'est jamais transmis au LLM, qui ne reçoit que le résultat vrai/faux de `check_flag`.
- La description, les fichiers et les sorties d'outils sont encadrés comme données non fiables ;
  les outils refusent tout fichier hors de l'espace de travail du run.
- Le shell (`--shell`) tourne sous un utilisateur sans privilèges, sans réseau, avec un délai
  maximal ; le clone de la base, qui contient les solutions, lui est rendu illisible et l'agent
  vérifie qu'il l'est avant de démarrer. Chaque commande et sa sortie vont dans la trace.
- La trace est écrite par le code, jamais retouchée ; `verify-trace` détecte toute modification.
- Les prompts ne contiennent aucune solution ni write-up. Les fichiers de solution rangés dans
  les dossiers de la base CSAW (`solution/`, `solve.py`, `writeup.md`, `flag.txt`) ne sont jamais
  copiés : seuls les fichiers listés dans `files` le sont, et un garde-fou écarte tout nom suspect.
- Les challenges de `tests/fixtures/` ont été créés pour ce projet et ne viennent d'aucune compétition.

## Documentation

- Base officielle CSAW 2026 (format, solutions écartées, limites) : [docs/csaw-2026.md](docs/csaw-2026.md)

Document de conception : https://claude.ai/artifact/6SttWmKq4MwDtjhUHTHtpj
