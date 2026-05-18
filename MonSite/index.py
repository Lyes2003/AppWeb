# Copyright 2024
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
import re
import os
from flask import Flask, url_for, render_template, g, request, redirect, session, flash, abort, send_file
from database import Database
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import timedelta
from flask_wtf import CSRFProtect   # import: active CSRF via Flask-WTF
from forms import RechercheForm, DeleteDocumentForm, AddCoursForm
from flask_wtf.csrf import CSRFError
from werkzeug.utils import secure_filename
from config import SECRET_KEY
from auth.routes import auth
from admin.gestioncours import managcours
from admin.gestionchapitres import managchapters
from admin.gestiondocuments import managdocuments
from utils import get_db, User, is_safe_url, is_valid_email, is_valid_name, is_strong_password

app = Flask(__name__, static_url_path="", static_folder="static")

# Configuration de l'application Flask
app.config['SECRET_KEY'] = SECRET_KEY # clé secrète pour les sessions et CSRF

if not app.config['SECRET_KEY']:
    raise RuntimeError("Secret key est pas définie")

csrf = CSRFProtect(app)  # active la protection CSRF pour l'application
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads') # dossier PRIVÉ (je l'ai mis hors de static/) pour les fichiers PDF téléchargés par l'admin
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True) # crée le dossier s'il n'existe pas

# Configuration des cookies de session pour la sécurité
app.config['REMEMBER_COOKIE_NAME'] = 'my_flask_app_remember' # Nom du cookie "se souvenir de moi"
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=15) # Durée de vie du cookie "se souvenir de moi"
app.config['SESSION_COOKIE_SECURE'] = False # permet d'envoyer le cookie uniquement via HTTPS (mettre à True en production avec HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True # Empêche l'accès JavaScript au cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protège contre les attaques CSRF

# --- Flask-Login setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login' # la redirection si l'utilisateur n'est pas connecté ou n'a pas les droits nécessaires

app.register_blueprint(auth, url_prefix='/auth') # enregistrer le blueprint 
app.register_blueprint(managcours, url_prefix='/admin') # enregistrer le blueprint admin
app.register_blueprint(managchapters, url_prefix='/admin') # enregistrer le blueprint admin
app.register_blueprint(managdocuments, url_prefix='/admin') # enregistrer le blueprint admin


# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    utilisateur = db.get_utilisateur(int(user_id))
    if utilisateur:
        # Récupère le statut admin depuis la BDD (par défaut False si manquant)
        is_admin = utilisateur.get('is_admin', False)
        return User(utilisateur['id_utilisateur'], utilisateur['nom'], utilisateur['courriel'], is_admin)
    return None

# fermeture de la connexion à la base de données après chaque requête
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.disconnect()

# Route pour la page d'accueil
@app.route('/', methods=['GET'])
def page_acceuil():
    return render_template('index.html')
# retourne à la page d'accueil après la déconnexion
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('page_acceuil'))

# Route pour le tableau de bord utilisateur
# retourne la page du tableau de bord avec le nom de l'utilisateur connecté
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    form = RechercheForm()
    cours = db.get_cours()
    cours_aleatoire = random.sample(cours, min(9, len(cours))) # Sélectionne jusqu'à 9 cours aléatoires
    return render_template('dashboard.html', nom=current_user.nom, cours=cours_aleatoire, form=form)

# Gestion des erreurs CSRF
@app.errorhandler(CSRFError) # appelle cette fonction en cas d'erreur CSRF
def handle_csrf_error(e):
    # message de secours si description manquante
    reason = getattr(e, "description", None) or str(e) or "Jeton CSRF manquant ou invalide." # message par défaut
    app.logger.warning("CSRF failure: %s (path=%s, ip=%s)", reason, request.path, request.remote_addr) # log de l'erreur CSRF
    return render_template("csrf_error.html", reason=reason), 400

# route pour le paneau d'administration
# pour ajouter supprimer ou modifier des cours
# accessible uniquement aux administrateurs
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)  # fait echouer la requête si l'utilisateur n'est pas admin
    db = get_db()
    form = AddCoursForm()
    cours = db.get_cours()
    chapitres = db.get_chapitres()
    documents = db.get_documents()

    # Calculer le nombre de chapitres pour chaque cours
    for c in cours:
        c['nbr_chapitres'] = db.count_chapitres_par_cours(c['id_cours']) # compte le nombre de chapitre par cours

    # Calculer le nombre de documents pour chaque chapitre
    for chapt in chapitres:
        chapt['nbr_documents'] = db.count_documents_par_chapitre(chapt['id_chapitre']) # compte le nombre de documents par chapitre

    return render_template('admin.html', form=form, cours=cours, chapitres=chapitres, documents=documents)

@app.route('/recherche', methods=['POST'])  
@login_required
def recherche():
    form = RechercheForm() # crée le formulaire de recherche
    if form.validate_on_submit():
        recherche_term = form.recherche.data.strip()
        if not recherche_term:
            return redirect(url_for('dashboard'))
        
        db = get_db()
        cours = db.get_cours() # obtenir tous les cours
        term = recherche_term.lower()
        # filtrer les cours qui correspondent à la recherche
        results = [c for c in cours if term in c['nom_cours'].lower()]
        return render_template('dashboard.html', form=form, results=results, query=recherche_term, nom=current_user.nom)
    return redirect(url_for('dashboard'))  

if __name__ == '__main__':
    app.run(debug=True, port=5001)