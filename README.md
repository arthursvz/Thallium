<pre>
  _______ _    _        _ _ _             
 |__   __| |  | |      | | (_)            
    | |  | |__| | __ _ | | |_ _ __   __ _ 
    | |  |  __  |/ _` || | | | '_ \ / _` |
    | |  | |  | | (_| || | | | | | | (_| |
    |_|  |_|  |_|\__,_||_|_|_|_| |_|\__, |
                                     __/ |
                                    |___/ 
</pre>


# Thallium 🔒✨

Bienvenue sur **Thallium** !

Suite d'outils modernes et sécurisés pour la gestion, la protection et l'authentification de vos fichiers. Chaque script a un usage précis, détaillé ci-dessous.

---



## 🚀 Fonctionnalités principales

### `encryptor.py` — Chiffrement/déchiffrement
- Chiffre ou déchiffre des fichiers et dossiers (récursivement) avec AES-GCM
- Choix de la clé : unique, par fichier, ou auto-générée par dossier
- Suppression sécurisée des fichiers originaux après chiffrement (optionnelle)
- Interface CLI conviviale

### `decryptor.py` — Déchiffrement rapide
- Déchiffre les fichiers chiffrés par `encryptor.py`
- Restaure les fichiers à leur état d'origine

### `cleaner.py` — Nettoyage sécurisé
- Supprime de façon sécurisée les fichiers temporaires ou sensibles
- Peut effacer de manière récursive un dossier ou une liste de fichiers
- Idéal pour garantir la non-récupérabilité des données supprimées

### `bruteforce.py` — Test de robustesse de mot de passe
- Permet de tester la robustesse d'un mot de passe par attaque brute-force (usage pédagogique)
- Peut servir à sensibiliser sur l'importance de mots de passe forts

### `authenticator.py` — Signature et vérification de fichiers
- Ajoute une signature cryptographique et des métadonnées à n'importe quel fichier
- Permet de vérifier l'intégrité et l'authenticité d'un fichier signé
- Fonctionne sur tout type de fichier (texte, binaire, image, etc.)
- Possibilité de restaurer le fichier original (suppression de la signature)

### `test.py` — Tests unitaires et de validation
- Permet de valider le bon fonctionnement des modules principaux
- Peut être adapté pour vos propres scénarios de test

---


## 🛠️ Utilisation rapide

1. Placez vos fichiers/dossiers à protéger dans le dossier de travail
2. Lancez le script souhaité selon votre besoin :
   - Chiffrement :
     ```bash
     python3 encryptor.py
     ```
   - Déchiffrement :
     ```bash
     python3 decryptor.py
     ```
   - Nettoyage sécurisé :
     ```bash
     python3 cleaner.py
     ```
   - Test de robustesse :
     ```bash
     python3 bruteforce.py
     ```
   - Authentification (signature/vérification) :
     ```bash
     python3 authenticator.py
     ```
   - Tests :
     ```bash
     python3 test.py
     ```
3. Suivez les instructions à l'écran pour chaque outil.

---

## ⚠️ Sécurité

- **Gardez vos clés précieusement !** Sans la clé, vos données sont irrécupérables. 
- Le projet est open source : auditez-le, améliorez-le, partagez-le !

---


## 💻 Compatibilité

- Linux, Windows, MacOS (nécessite Python 3 et le module `cryptography`)
- Installation des dépendances :
  ```bash
  pip install -r requirements.txt
  ```

---



## 📄 Licence

Ce projet est sous licence GNU AGPL v3. Utilisation libre, modification et partage encouragés, dans le respect de la communauté du logiciel libre !
Voir le fichier LICENSE pour les détails complets.

---


## 👨‍💻 Auteur

Arthur SAUVEZIE — 2025

---


✨ Bon chiffrement et bonne sécurité avec Thallium ! ✨
