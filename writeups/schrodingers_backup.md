# Write-up — Schrödinger's Backup (forensics)

> Rédigé à partir de la trace de **notre** agent (run #14 du 2026-11-10, modèle `moonshotai/kimi-k3.1-pro` via OpenRouter). Décrit uniquement la démarche de l'agent, telle que la trace vérifiée l'enregistre.

| | |
| --- | --- |
| Catégorie | Forensics (SQLite WAL, reconstruction de transactions) |
| Fichiers | `README.md`, `evidence.zip` (base `catalog.db` + `catalog.db-wal`, `capsule.json`, `recorder.py`, `OPERATIONS.md`) |
| Flag | `csaw{th3_c4t_c0mm1tt3d_but_th3_j0urn4l_r3m3mb3r5}` |
| Validé par `check_flag` (hors LLM) | oui, source `auto:shell` |
| Actions du LLM | 21 · Durée 322,9 s · Trace intègre (chaîne SHA-256) |

## Énoncé

Une base SQLite accompagnée de son journal **WAL** (Write-Ahead Log). Une « capsule » chiffrée (`capsule.json`) ne s'ouvre qu'avec une clé dérivée de l'**état réellement validé** de la base. Tout l'enjeu : distinguer les transactions *committées* des résidus d'un WAL partiellement réécrit.

## Démarche de l'agent

1. **Cartographie.** L'agent lit le README, `OPERATIONS.md` et `recorder.py`. Il comprend que deux contrôleurs (« north » / « south ») stockent chacun une part de 32 octets, dont le XOR est le jeton courant, et que la clé de la capsule est `SHA256(DOMAIN + concaténation des jetons de tout l'historique validé)`.
2. **SQLite indisponible.** Les ouvertures via `sqlite3` échouent dans le bac à sable (permissions, mode immutable). Plutôt que d'insister, l'agent **parse le format binaire à la main** : pages de 1024 octets, en-tête WAL, frames de 24 + 1024 octets.
3. **Validation cryptographique du WAL.** L'agent réimplémente l'**algorithme de checksum WAL de SQLite** et le fait courir frame par frame. Il établit que le préfixe valide s'arrête au commit de la frame 34/37 ; les frames suivantes sont une transaction inachevée (35–37) et un ancien WAL d'une génération antérieure (38–39).
4. **Reconstruction de l'historique.** En rejouant uniquement les frames validées, transaction par transaction (en respectant la sémantique « état testé au commit » décrite dans les notes), l'agent reconstitue la suite exacte des jetons — c'est là que les premiers essais, qui échantillonnaient des frames intermédiaires, échouaient.
5. **Dérivation de la clé et déchiffrement.** `SHA256` de la concaténation des jetons → clé AES-GCM. La capsule se déchiffre **sans erreur d'authentification** avec le préfixe de 37 frames, confirmant que c'est bien l'historique canonique. Le plaintext est le flag, validé par `check_flag`.

## Ce qui a bien fonctionné

- **Parsing binaire du WAL de zéro** quand SQLite était inutilisable : en-têtes, frames, et surtout la **vérification des checksums** pour séparer committé / non committé.
- **Lecture attentive des notes** (`OPERATIONS.md`) pour corriger une erreur de méthode : tester l'état `armed` au commit, pas sur chaque frame.
- **Validation par l'authentification AES-GCM** : l'agent ne « devine » pas l'historique, il le confirme par le fait que le tag GCM passe.
- Résilience aux permissions du bac à sable (scripts repassés par `/tmp` et par stdin).

## Points remarquables pour l'évaluation

- Le pré-scan a trouvé des gabarits `csaw{...}` dans le README et l'archive ; `check_flag`, **hors LLM**, les a rejetés. Seul le flag déchiffré a été validé.
- Résolution entièrement locale (shell confiné `ctfsandbox`, réseau coupé). 21 actions, dont une longue phase d'ingénierie binaire — le challenge le plus coûteux de nos résolutions (322 s).
