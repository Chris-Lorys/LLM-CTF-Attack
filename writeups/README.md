# Write-ups — challenges résolus par l'agent (CSAW 2026)

**7 challenges résolus sur 23**, répartis sur 5 des 6 catégories (misc, rev, forensics, crypto, web ; reste 0 en pwn). Chaque write-up est rédigé à partir de la trace de **notre** agent uniquement ; aucune solution des organisateurs n'a été consultée ni fournie au modèle.

| Challenge | Catégorie | Flag | Modèle | Actions |
| --- | --- | --- | --- | --- |
| [House of Hollow Houses](house_of_hollow_houses.md) | misc / web | `csaw{w4nd3r3r_0f_th3_h0ll0w_h0us3}` | qwen-3.8-27b (Cerebras) | 6 |
| [Autobahn](autobahn.md) | rev — code auto-modifiant | `csaw{c0d3_th4t_rewr1t3s_1ts3lf_c4nt_b3_tru5t3d}` | DeepSeek V4.1 Flash | 18 |
| [Machine Head](machine_head.md) | rev — machine virtuelle | `csaw{cl1mb1ng_th3_v1rtu4l_st4ck_0n3_0pc0d3_4t_4_t1m3}` | qwen-3.8-27b (Cerebras) | 19 |
| [Hemispheres](hemispheres.md) | forensics — polyglotte/LSB | `csaw{0n3_f1l3_tw0_truth5_p0lygl0t_m4g1c}` | DeepSeek V4.1 Flash | 17 |
| [Secret Treaties](secret_treaties.md) | crypto — sac à dos / LLL | `csaw{LLL_turns_kn4ps4cks_1nt0_p4nc4k3s_wh3n_d3ns1ty_1s_l0w}` | Kimi K3.1 Pro | 12 |
| [Schrödinger's Backup](schrodingers_backup.md) | forensics — SQLite WAL | `csaw{th3_c4t_c0mm1tt3d_but_th3_j0urn4l_r3m3mb3r5}` | Kimi K3.1 Pro | 21 |
| [Juggler](juggler.md) | web — mass assignment / type juggling | `csaw{tw0_f0r_0n3_2gc9w2hz}` | Kimi K3.1 Pro | 15 |

## Garanties communes à toutes les résolutions

- **Flag validé hors LLM** par `check_flag` contre le fichier `.json` fourni : le modèle ne peut pas « déclarer » une victoire. Les gabarits `csaw{...}` trouvés dans les fichiers ont systématiquement été rejetés.
- **Trace complète et non retouchée**, chaînée par SHA-256 ; intégrité revérifiable par `python -m csaw_agent verify-trace trace.jsonl`.
- **Rapport généré automatiquement** à partir de la trace (`rapport.md`), sans intervention humaine ni LLM.
- **Shell confiné** (utilisateur `ctfsandbox`, réseau coupé, base de challenges protégée) ; pour les challenges à serveur, l'agent reçoit un outil réseau borné au seul service du challenge.
- **Aucune intervention humaine** pendant la résolution.

## Ce que montrent les traces (au-delà du nombre de flags)

- **Écrire l'outil manquant** plutôt que l'invoquer : décodeur PNG maison (Hemispheres), LLL réimplémenté en précision décimale (Secret Treaties), parseur binaire du WAL SQLite (Schrödinger's Backup), patch du binaire pour re-désassembler du code auto-modifiant (Autobahn).
- **Chaîner plusieurs vulnérabilités** et s'auto-corriger sans aide (Juggler : mass assignment + type juggling ; Autobahn : octet manquant corrigé seul).
- **Choisir l'attaque sur une mesure, pas une intuition** (densité du sac à dos → réseau plutôt que super-croissant).

## Où trouver les traces brutes

Artefacts `runs` des runs GitHub Actions (workflow `essai csaw`) :
`42853273654` (house_of_hollow_houses, machine_head), `42871163931` (autobahn, hemispheres), `42897200300` (secret_treaties, schrodingers_backup), `42903744855` (juggler). Chaque dossier contient `trace.jsonl` + `rapport.md`. Le workflow `exporter rapports` réimprime les rapports d'un run à la demande, et `assembler soumission` produit le dossier de soumission complet.
