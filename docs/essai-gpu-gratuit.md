# Premier essai sur GPU gratuit

Le PC de développement n'a pas de GPU dédié. Les vrais essais tournent donc sur Kaggle ou Colab,
soit avec l'API Gemini gratuite, soit avec un modèle ouvert servi par Ollama sur le GPU gratuit. Tout est dans le notebook
[`notebooks/essai_gpu_gratuit.ipynb`](../notebooks/essai_gpu_gratuit.ipynb) : il n'y a rien à
installer sur le PC.

## Avec l'API Gemini gratuite (réglage par défaut)

Par défaut, `MODEL = "gemini:gemini-2.5-flash"`. C'est un modèle de pointe, gratuit dans la limite d'un
quota par minute et par jour. L'agent espace ses appels d'environ 7 s. Si le serveur répond 429
(quota dépassé), il attend puis réessaie. Quand le quota du jour est épuisé, les challenges restants
finissent en `erreur_llm`, mais le bilan est quand même écrit. Il suffit de relancer le lendemain avec
`CATEGORIES` restreint.

1. Créer une clé sur https://aistudio.google.com/apikey (compte Google, sans carte bancaire).
2. Kaggle : *Add-ons* → *Secrets* → *Add secret*, nom `GEMINI_API_KEY`, valeur = la clé, puis cocher
   la case du notebook. Colab : icône 🔑, même nom, activer « Accès au notebook ».
3. Pas besoin de GPU : *Accelerator* peut rester sur *None*. Il faut seulement *Internet* = **On**.

La clé passe uniquement par la variable d'environnement `CSAW_API_KEY` du processus de l'agent. Elle
n'apparaît ni dans la trace, ni dans les résultats, ni dans le shell en bac à sable (environnement vidé).

Pour revenir au modèle local, mettre `MODEL = "ollama:qwen2.5:32b"` et choisir le GPU T4 x2.

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
| Paramètres | `MODEL`, `BRANCH`, `CHALLENGES` (`csaw` ou `demo`), `CATEGORIES`, `SKIP_SERVER`, `MAX_STEPS` : la seule cellule à modifier |
| Modèle | clé `GEMINI_API_KEY` lue dans les secrets, ou, pour `ollama:`, installation d'Ollama, démarrage avec un contexte de 16 384 jetons, téléchargement du modèle |
| Agent | clonage du dépôt, exécution des tests |
| Lancement | clone de la base CSAW 2026, puis `run-all <base>/dataset.json --skip-server --model <MODEL>` |
| Contrôle | `verify-trace` sur chaque trace, bilan, affichage d'un rapport |
| Résultats | archive avec `trace.jsonl` et `rapport.md` par challenge, plus `bilan.json` |

## Choix du modèle

| Modèle | Mémoire GPU (environ) | Usage |
| --- | --- | --- |
| `qwen2.5:7b` | 5 Go | premier essai, rapide |
| `qwen2.5:14b` | 9 Go | essai suivant, meilleur raisonnement, tient sur une T4 |
| `qwen2.5-coder:14b` | 9 Go | à comparer sur les challenges rev et pwn |
| `qwen2.5:32b` | 20 Go | réparti sur les 2 T4 (GPU T4 x2 obligatoire), environ 2 fois plus lent que le 14b |

Pour tester ses propres challenges, les déposer dans un *Dataset* Kaggle (un dossier par challenge,
avec son `challenge.json`), l'ajouter au notebook (*Add Input*) et mettre
modifier `CHALLENGES_DIR` dans la cellule de lancement : `"/kaggle/input/<nom-du-dataset>"`.

## Si quelque chose bloque

- **« Ollama n'a pas démarré »** : la cellule affiche la fin du journal `/tmp/ollama.log`.
- **`erreur_llm` dans le bilan** : le modèle n'a pas répondu à temps (5 minutes par réponse). Relancer,
  ou prendre un modèle plus petit.
- **`reponses_illisibles`** : le modèle ne suit pas le format JSON. C'est fréquent sous 7 milliards
  de paramètres ; passer à `qwen2.5:14b`.
