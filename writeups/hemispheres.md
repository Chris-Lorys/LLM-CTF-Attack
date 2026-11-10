# Write-up — Hemispheres (forensics)

> Rédigé à partir de la trace de **notre** agent (run #12 du 2026-11-10, modèle `deepseek/deepseek-v4.1-flash-1017` via OpenRouter). Décrit uniquement la démarche de l'agent, telle que la trace vérifiée l'enregistre.

| | |
| --- | --- |
| Catégorie | Forensics (stéganographie / polyglotte) |
| Fichiers | `README.md`, `the_signal.png` (image PNG, 8 612 octets) |
| Flag | `csaw{0n3_f1l3_tw0_truth5_p0lygl0t_m4g1c}` |
| Validé par `check_flag` (hors LLM) | oui, source `auto:read_file` |
| Actions du LLM | 17 · Durée 60,4 s · Trace intègre (chaîne SHA-256) |

## Énoncé

« Hemispheres » : les organisateurs n'ont fourni qu'une image. Le README précise que *différents programmes lisent le fichier depuis des extrémités différentes* — indice d'un fichier **polyglotte**.

## Démarche de l'agent

1. **Reconnaissance.** `file_info` et `strings` sur `the_signal.png`. L'agent repère un chunk `tEXt` « Comment » : *« Look past IEND for the lock. The key is in the pixels, not the words. »* et, en fin de fichier, les noms `flag.txt` / `README.txt` — signature d'une archive ZIP accolée.
2. **Séparation du polyglotte.** L'agent coupe le fichier après le marqueur `IEND` (offset 8 286) et écrit les 326 octets restants dans `embedded.zip`. L'archive est chiffrée : il faut une clé.
3. **Absence de PIL.** Premier réflexe `from PIL import Image` → `ModuleNotFoundError`. L'agent ne s'arrête pas : il **écrit son propre décodeur PNG** en `zlib` + `struct`, parcourt les chunks, décompresse l'`IDAT` et applique le défiltrage par ligne pour reconstituer les pixels bruts.
4. **Extraction LSB par canal.** Sur les pixels reconstitués, l'agent lit le bit de poids faible de chaque canal séparément. Le canal bleu livre une chaîne lisible : `r3ad_b3tw33n_th3_p1x3ls`.
5. **Ouverture de l'archive.** `extract(embedded.zip, password="r3ad_b3tw33n_th3_p1x3ls")` réussit ; `read_file(flag.txt)` donne le flag, validé par `check_flag`.

## Ce qui a bien fonctionné

- **Diagnostic polyglotte dès l'étape 1** à partir du commentaire PNG et des noms de fichiers en queue.
- **Décodeur PNG écrit de zéro** faute de PIL : décompression `IDAT`, défiltrage, puis extraction LSB canal par canal — une vraie démarche forensique, pas l'appel d'un outil clé en main.
- **Résilience aux permissions** : les scripts écrits sur disque n'étant pas exécutables dans le bac à sable, l'agent les a repassés par l'entrée standard (`python3 - < script`).

## Points remarquables pour l'évaluation

- Le pré-scan déterministe a trouvé le gabarit `csaw{...}` du README ; `check_flag`, **exécuté hors LLM**, l'a rejeté. Seul le flag extrait de l'archive chiffrée a été validé.
- Résolution entièrement locale (shell confiné `ctfsandbox`, réseau coupé), par reconstruction manuelle du format d'image.
