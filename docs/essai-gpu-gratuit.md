# Premier essai sur GPU gratuit

Le PC de développement n'a pas de GPU dédié. Les vrais essais tournent donc sur un GPU gratuit,
avec un modèle ouvert servi par Ollama. Tout est dans le notebook
[`notebooks/essai_gpu_gratuit.ipynb`](../notebooks/essai_gpu_gratuit.ipynb) : il n'y a rien à
installer sur le PC et aucune clé d'API à fournir.

## Kaggle (recommandé : 30 h de GPU par semaine)

1. Créer un compte sur kaggle.com et **vérifier le numéro de téléphone**
   (*Settings* → *Phone verification*). Sans cette vérification, ni le GPU ni Internet ne sont proposés.
2. *Create* → *New Notebook*, puis *File* → *Import Notebook* → onglet *GitHub*, et coller
   `https://github.com/Chris-Lorys/LLM-CTF-Attack/blob/main/notebooks/essai_gpu_gratuit.ipynb`.
3. Dans le panneau de droite, *Session options* : *Accelerator* = **GPU T4 x2**, *Internet* = **On**.
4. *Run all*. Compter environ 5 minutes d'installation, puis quelques minutes par challenge.
5. Récupérer `runs-<modèle>.zip` dans l'onglet *Output*.

## Colab (solution de secours)

1. Ouvrir
   `https://colab.research.google.com/github/Chris-Lorys/LLM-CTF-Attack/blob/main/notebooks/essai_gpu_gratuit.ipynb`.
2. *Exécution* → *Modifier le type d'exécution* → **GPU T4**.
3. *Exécution* → *Tout exécuter*. L'archive des résultats se télécharge à la fin.

## Ce que fait le notebook

| Étape | Détail |
| --- | --- |
| Paramètres | `MODEL`, `BRANCH`, `CHALLENGES_DIR`, `MAX_STEPS` : la seule cellule à modifier |
| Ollama | installation, démarrage avec un contexte de 8 192 jetons, téléchargement du modèle |
| Agent | clonage du dépôt, exécution des tests |
| Lancement | `python -m csaw_agent run-all <dossier> --model ollama:<modèle>` |
| Contrôle | `verify-trace` sur chaque trace, bilan, affichage d'un rapport |
| Résultats | archive avec `trace.jsonl` et `rapport.md` par challenge, plus `bilan.json` |

## Choix du modèle

| Modèle | Mémoire GPU (environ) | Usage |
| --- | --- | --- |
| `qwen2.5:7b` | 5 Go | premier essai, rapide |
| `qwen2.5:14b` | 9 Go | essai suivant, meilleur raisonnement, tient sur une T4 |
| `qwen2.5-coder:14b` | 9 Go | à comparer sur les challenges rev et pwn |

Pour tester ses propres challenges, les déposer dans un *Dataset* Kaggle (un dossier par challenge,
avec son `challenge.json`), l'ajouter au notebook (*Add Input*) et mettre
`CHALLENGES_DIR = "/kaggle/input/<nom-du-dataset>"`.

## Si quelque chose bloque

- **« Ollama n'a pas démarré »** : la cellule affiche la fin du journal `/tmp/ollama.log`.
- **`erreur_llm` dans le bilan** : le modèle n'a pas répondu à temps (5 minutes par réponse). Relancer,
  ou prendre un modèle plus petit.
- **`reponses_illisibles`** : le modèle ne suit pas le format JSON. C'est fréquent sous 7 milliards
  de paramètres ; passer à `qwen2.5:14b`.
