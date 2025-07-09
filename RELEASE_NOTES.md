# Release Notes — Secure Bundle (Thallium)

## Version 1.0 — Juillet 2025

### Nouveautés majeures

- **Nouveau script principal : `secure_bundle.py`**
  - Chiffrement et signature de fichiers ou dossiers entiers (récursif) avec une seule commande.
  - Ajout de métadonnées personnalisées (auteur, lieu, message, date, heure) à chaque fichier chiffré.
  - Génération, sauvegarde et chargement automatique de la clé (format base64, 32 octets).
  - Vérification de la signature, affichage des métadonnées et déchiffrement en un seul outil.
  - Suppression sécurisée (optionnelle) des fichiers originaux, des fichiers chiffrés et de la clé, avec avertissements.
  - Interface 100% en anglais, prompts clairs et robustes.
  - Gestion des erreurs améliorée (clé manquante, format de clé, fichiers non trouvés, etc).
  - Compatible fichiers et dossiers, y compris structure de sous-dossiers.
  - Suppression de la clé .key pour un dossier : la clé n'est supprimée qu'une seule fois à la racine.
  - Les métadonnées et la question de suppression ne sont posées qu'une seule fois pour tout le lot.

### Améliorations générales

- Documentation enrichie dans le README pour mettre en avant `secure_bundle.py`.
- Les anciens scripts (`encryptor.py`, `decryptor.py`, `authenticator.py`) restent disponibles pour compatibilité, mais l'usage recommandé est désormais `secure_bundle.py`.
- Nettoyage du code, robustesse accrue, gestion des chemins et des erreurs améliorée.

### Sécurité

- Toutes les opérations de chiffrement utilisent AES-GCM (256 bits).
- Les signatures sont basées sur SHA256.
- Les clés ne sont jamais stockées en clair dans les fichiers chiffrés.
- Avertissements explicites avant toute suppression irréversible.

---

✨ Merci d'utiliser Thallium ! Pour toute suggestion ou bug, ouvrez une issue ou contactez l'auteur. ✨
