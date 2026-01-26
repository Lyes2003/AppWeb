
## Auteur


## Description


## Prérequis
- Python 3.x
- pip
- Flask 3.x

## Installation

### Windows (PowerShell)
1) Ouvrir un terminal dans le dossier du projet

2) Créer un environnement virtuel :
```powershell
python -m venv venv
```
3) Activer l’environnement : 
```powershell
.\venv\Scripts\Activate.ps1
```
4) Installer les dépendances :
```powershell
pip install -r MonSite/requirements.txt
```

---

### Linux / macOS
1) Ouvrir un terminal et se placer dans le dossier du projet ou directement dans `MonSite` :
```bash
cd MonSite
```
2) Créer et activer un environnement virtuel :
```bash
python3 -m venv venv
source venv/bin/activate
```
3) Mettre `pip` à jour puis installer les dépendances :
```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```
4) Initialiser la base de données SQLite (une seule fois) :
```bash
sqlite3 db/maBase.db < db/maBase.sql
```
5) Lancer l'application en développement, deux facon de le faire :
```bash
# en utilisant flask
export FLASK_APP=index.py
flask run

# en executent directement
python index.py
```

**Remarques**
- Activez le venv avant d'installer des paquets pour éviter des conflits avec l'installation Python système.
- Si l'installation échoue (message "This environment is externally managed"), créez et utilisez un venv local comme expliqué ci‑dessus.
