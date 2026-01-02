# Copyright 2024 <Votre nom et code permanent>
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

import re
import os
from flask import Flask, url_for, render_template, g, request, redirect, session, flash, abort
from database import Database
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import timedelta
from urllib.parse import urlparse, urljoin

app = Flask(__name__, static_url_path="", static_folder="static")

# Configuration de l'application Flask
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_me_secure_key')

# Configuration des cookies de session pour la sécurité
app.config['REMEMBER_COOKIE_NAME'] = 'my_flask_app_remember' # Nom du cookie "se souvenir de moi"
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=15) # Durée de vie du cookie "se souvenir de moi"
app.config['SESSION_COOKIE_SECURE'] = True # Utiliser True en production avec HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Empêche l'accès JavaScript au cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protège contre les attaques CSRF

# --- Flask-Login setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#--- User class for Flask-Login ---
class User(UserMixin):
    def __init__(self, id_utilisateur, nom, courriel):
        self.id = id_utilisateur
        self.nom = nom
        self.courriel = courriel

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    utilisateur = db.get_utilisateur(int(user_id))
    if utilisateur:
        return User(utilisateur['id_utilisateur'], utilisateur['nom'], utilisateur['courriel'])
    return None

# Database connection management
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        g._database = Database()
    return g._database

# Close database connection at the end of request
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.disconnect()

# Route pour la page d'accueil
@app.route('/', methods=['GET'])
def page_acceuil():
    return render_template('index.html')

# Route pour la page d'inscription
@app.route('/inscription', methods=['GET', 'POST'])
def inscription():
    if request.method == 'GET':
        return render_template('register.html')
    else:
        nom = request.form['nom'].strip()
        courriel = request.form['courriel'].strip()
        mot_de_passe = request.form['mot_de_passe'].strip()
        mot_de_passe_confirm = request.form['mot_de_passe_confirm'].strip()
        # Vérifier si les mots de passe correspondent
        if mot_de_passe != mot_de_passe_confirm:
            return render_template('register.html', error="Les mots de passe ne correspondent pas.")
        # Vérifier si un utilisateur avec le même courriel existe déjà
        db = get_db()
        existing = db.get_utilisateur_par_courriel(courriel)
        if existing:
            return render_template('register.html', error="Un compte existe déjà pour ce courriel.")
        hashed = generate_password_hash(mot_de_passe)
        # Insérer le nouvel utilisateur dans la base de données
        id = db.insert_utilisateur(nom, courriel, hashed)
        return redirect(url_for('page_acceuil'))

# Route pour la page de connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        courriel = request.form['courriel'].strip()
        mot_de_passe = request.form['mot_de_passe'].strip()
        db = get_db()
        utilisateur = db.get_utilisateur_par_courriel(courriel)
        # Vérifier si l'utilisateur existe et si le mot de passe est correct
        if utilisateur and check_password_hash(utilisateur['mot_de_passe'], mot_de_passe):
            user_obj = User(utilisateur['id_utilisateur'], utilisateur['nom'], utilisateur['courriel'])
            # Connecter l'utilisateur et gérer la session 
            login_user(user_obj, remember='remember' in request.form)
            # Rediriger vers la page suivante ou la page d'accueil
            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for('page_acceuil'))
        else:
            return render_template('login.html', error="Courriel ou mot de passe incorrect.")

# Route pour la déconnexion
@app.route('/logout')
@login_required
def logout():
    
    logout_user()
    return redirect(url_for('page_acceuil'))

# Route pour une page protégée
@app.route('/protected')
@login_required
def protected():
    return f"Bonjour {current_user.nom} — page protégée"

# Fonction pour vérifier si une URL est sûre
def is_safe_url(target):
    host_url = request.host_url # Obtenir l'URL de l'hôte
    ref_url = urlparse(host_url) # Analyser l'URL de l'hôte
    test_url = urlparse(urljoin(host_url, target)) # Joindre l'URL de l'hôte avec la cible 
    return test_url.scheme in ('http', 'https') and ref_url.netloc == urlparse(test_url).netloc # Vérifier que le netloc correspond

if __name__ == '__main__':
    app.run(debug=True)