# inf3191-tp3-20252

# INF3191 — TP3  — Adoption d’animaux 

## Auteurs
- Chikh Lyes (CHIL68350302)
- GHERBI NADIR ABDELHAMID (GHEN86300304)

## Description
Application web Flask permettant :
- d’afficher une liste d’animaux disponibles (accueil `/`)
- de consulter la fiche détaillée d’un animal (`/pageAnimal/<id>`)
- de soumettre un animal à l’adoption (`/adoption`)
- de rechercher un animal (`/recherche`)
- d’afficher des pages d’erreur (404 général + animal introuvable)

## Prérequis
- Python 3.x
- pip
- Flask 3.x

## Installation (Windows / PowerShell)
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
pip install flask
pip install flask_login
