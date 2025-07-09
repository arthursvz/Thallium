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

Un outil simple, moderne et sécurisé pour chiffrer/déchiffrer vos fichiers et dossiers avec AES-GCM. Protégez vos données en toute simplicité, sans prise de tête ! 😎🔑

---


## 🚀 Fonctionnalités

- 🔐 Chiffrez ou déchiffrez des fichiers et dossiers (récursivement)
- 🗝️ Choisissez une clé unique, une clé par fichier, ou une clé auto-générée par dossier
- 🤖 Interface en ligne de commande conviviale
- 🐍 100% Python, aucune installation complexe
- 📝 Suppression sécurisée des fichiers originaux après chiffrement (optionnelle)
- 🧹 `cleaner.py` : Nettoyez les fichiers temporaires ou sensibles facilement
- 🕵️ `bruteforce.py` : Testez la robustesse de vos mots de passe (usage pédagogique)
- 🛡️ `authenticator.py` : Ajoutez une couche d'authentification à vos scripts

---

## 🛠️ Utilisation rapide

1. Placez vos fichiers/dossiers à protéger dans le dossier de travail
2. Lancez le script :
   ```bash
   python3 encryptor.py
   ```
3. Suivez les instructions à l'écran (choix du fichier/dossier, gestion des clés, suppression...)
4. Les fichiers chiffrés auront l'extension `.enc` et les clés peuvent être sauvegardées à côté 🔑

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

✨ Bon chiffrement avec Thallium ! ✨
