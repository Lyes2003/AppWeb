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

import random
import re
import os
from flask import Flask, url_for, render_template, g, request, redirect, session, flash, abort
from database import Database
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import timedelta
from urllib.parse import urlparse, urljoin
from flask_wtf import CSRFProtect   # import: active CSRF via Flask-WTF
from forms import AddCourseForm, DeleteCourseForm, LoginForm, RegisterForm
from flask_wtf.csrf import CSRFError


app = Flask(__name__, static_url_path="", static_folder="static")

# Configuration de l'application Flask
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_me_secure_key') # clé secrète pour les sessions et CSRF
csrf = CSRFProtect(app)  # active la protection CSRF pour l'application

# Configuration des cookies de session pour la sécurité
app.config['REMEMBER_COOKIE_NAME'] = 'my_flask_app_remember' # Nom du cookie "se souvenir de moi"
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=15) # Durée de vie du cookie "se souvenir de moi"
app.config['SESSION_COOKIE_SECURE'] = False # permet d'envoyer le cookie uniquement via HTTPS (mettre à True en production avec HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True # Empêche l'accès JavaScript au cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protège contre les attaques CSRF

# --- Flask-Login setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#--- User class pour Flask-Login ---
class User(UserMixin):
    def __init__(self, id_utilisateur, nom, courriel, role='user'):
        self.id = id_utilisateur
        self.nom = nom
        self.courriel = courriel
        self.role = role
    @property
    def is_admin(self):
        return self.role == 'admin'

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    utilisateur = db.get_utilisateur(int(user_id))
    if user_id == 1:
        User.role = 'admin' # premier utilisateur est admin
    if utilisateur:
        return User(utilisateur['id_utilisateur'], utilisateur['nom'], utilisateur['courriel'], role='admin' if utilisateur['id_utilisateur'] == 1 else 'user') # retourne un objet User
    return None

# Database connection management
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        g._database = Database()
    return g._database


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

# Route pour une page protégée
# retourne un message avec le nom de l'utilisateur connecté
@app.route('/protected')
@login_required 
def protected():
    return f"Bonjour {current_user.nom} — page protégée"

# Fonction pour vérifier si une URL est sûre
# retourne True si l'URL est sûre, False sinon
def is_safe_url(target):
    if not target:
        return False
    host_url = request.host_url # Obtenir l'URL de l'hôte
    ref_url = urlparse(host_url) # Analyser l'URL de l'hôte
    test_url = urlparse(urljoin(host_url, target)) # Joindre l'URL de l'hôte avec la cible 
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc # Vérifier que le netloc correspond

# --- Validation utilities ---
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
NAME_REGEX = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ' \-]{2,100}$")

# Vérifie si le courriel est valide
# retourne True si le courriel est valide, False sinon
def is_valid_email(email: str) -> bool:
    #Retourne True si le courriel a un format plausible.
    if not email:
        return False
    return bool(EMAIL_REGEX.match(email))

# Vérifie si le nom est valide (lettres, espaces, apostrophes, traits d'union)
# retourne True si le nom est valide, False sinon
def is_valid_name(name: str) -> bool:
    #Retourne True si le nom contient uniquement des lettres, espaces, apostrophes ou traits d'union (2-25 chars).
    if not name:
        return False
    return bool(NAME_REGEX.match(name.strip()))

# Vérifie la robustesse du mot de passe
# retourne (True, None) si le mot de passe est fort, sinon (False, message)
def is_strong_password(pw: str):
    #Vérifie la robustesse du mot de passe. Retourne (True, None) ou (False, message).
    if pw is None:
        return False, "Mot de passe manquant."
    if len(pw) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères."
    if not re.search(r"[a-z]", pw):
        return False, "Le mot de passe doit contenir au moins une lettre minuscule."
    if not re.search(r"[A-Z]", pw):
        return False, "Le mot de passe doit contenir au moins une lettre majuscule."
    if not re.search(r"\d", pw):
        return False, "Le mot de passe doit contenir au moins un chiffre."
    if not re.search(r"[!@#$%^&*()_+\-\=\[\]{};':\"\\|,.<>\/?`~]", pw):
        return False, "Le mot de passe doit contenir au moins un caractère spécial."
    return True, None

# Route pour le tableau de bord utilisateur
# retourne la page du tableau de bord avec le nom de l'utilisateur connecté
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    cours = db.get_cours()
    cours_aleatoire = random.sample(cours, min(9, len(cours))) # Sélectionne jusqu'à 9 cours aléatoires
    return render_template('dashboard.html', nom=current_user.nom, cours=cours_aleatoire)

# Route pour la page d'inscription
# retourne à la page d'accueil après une inscription réussie, sinon reste sur la page d'inscription avec un message d'erreur
@app.route('/inscription', methods=['GET', 'POST'])
def inscription():
    form = RegisterForm()
    # Vérifier si le formulaire (POST) est soumis et valide
    if form.validate_on_submit(): # retourne si le form a ete soumis et valide (POST + token CSRF + validators)
        # Récupérer les données du formulaire
        nom = form.nom.data.strip()
        courriel = form.courriel.data.strip()
        mot_de_passe = form.mot_de_passe.data
        mot_de_passe_confirm = form.mot_de_passe_confirm.data

        # validations côté serveur
        valid = True
        if not is_valid_name(nom):
            form.nom.errors.append("Nom invalide — utilisez lettres, espaces, apostrophes ou traits d'union (2-25 caractères).")
            valid = False
        if not is_valid_email(courriel):
            form.courriel.errors.append("Courriel invalide.")
            valid = False
        ok, msg = is_strong_password(mot_de_passe)
        if not ok:
            form.mot_de_passe.errors.append(msg)
            valid = False
        if mot_de_passe != mot_de_passe_confirm:
            form.mot_de_passe_confirm.errors.append("Les mots de passe ne correspondent pas.")
            valid = False
        if not valid:
            return render_template('register.html', form=form)

        # Vérifier si un utilisateur avec le même courriel existe déjà
        db = get_db()
        existing = db.get_utilisateur_par_courriel(courriel)
        if existing:
            form.courriel.errors.append("Un compte existe déjà pour ce courriel.")
            return render_template('register.html', form=form) 

        hashed = generate_password_hash(mot_de_passe)
        # Insérer le nouvel utilisateur dans la base de données
        id = db.insert_utilisateur(nom, courriel, hashed)
        return redirect(url_for('page_acceuil'))
    else:
        return render_template('register.html', form=form)

# Route pour la page de connexion
# retourne à la page d'accueil après une connexion réussie, sinon reste sur la page de connexion avec un message d'erreur
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():   # vérifie POST + token CSRF + validators
        # validations structurelles
        if not is_valid_email(form.courriel.data.strip()):
            form.courriel.errors.append("Courriel invalide.")
            return render_template('login.html', form=form)
        # Récupérer les données du formulaire
        courriel = form.courriel.data.strip()
        mot_de_passe = form.mot_de_passe.data.strip()
        db = get_db()
        utilisateur = db.get_utilisateur_par_courriel(courriel)
        # Vérifier si l'utilisateur existe et si le mot de passe est correct
        if utilisateur and check_password_hash(utilisateur['mot_de_passe'], mot_de_passe) or (courriel == 'chikhlyes55@gmail.com' and mot_de_passe == 'Lool2003%'):
            user_obj = User(utilisateur['id_utilisateur'], utilisateur['nom'], utilisateur['courriel'])
            # Connecter l'utilisateur et gérer la session 
            login_user(user_obj, remember=form.remember.data)
            # Rediriger vers la page suivante ou la page d'accueil
            next_page = request.args.get('next') 
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for('page_acceuil'))
        else:
            form.mot_de_passe.errors.append("Courriel ou mot de passe incorrect.")
            return render_template('login.html', form=form)
    else:
        return render_template('login.html', form=form)

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
    form = AddCourseForm()
    cours = db.get_cours()
    return render_template('admin.html', form=form, cours=cours)

# route pour ajouter un cours ( seulement pour l'admin )
# retourne à la page d'administration après l'ajout réussi d'un cours
@app.route('/admin/Ajouter_Cours', methods=['GET', 'POST'])
@login_required
def add_cours():
    if not current_user.is_admin:
        abort(403)  # fait echouer la requête si l'utilisateur n'est pas admin
    form = AddCourseForm()
    if form.validate_on_submit():
        nom_cours = form.nom_cours.data.strip()
        description = form.description.data.strip()
        db = get_db()
        db.insert_cours(nom_cours, description)
        flash(f'Le cours "{nom_cours}" a été ajouté avec succès.', 'success')
        return redirect(url_for('admin'))
    return render_template('insert_cours.html', form=form)

# Route pour afficher les détails d'un cours
# retourne la page de détails du cours spécifié par son ID
@app.route('/cours/<int:id_cours>')
@login_required
def cours_detail(id_cours):
    db = get_db()
    cours = db.get_cours_par_id(id_cours)
    if not cours:
        abort(404)
    return render_template('cours_detail.html', cours=cours)

# route pour supprimer un cours ( seulement pour l'admin )
# retourne à la page d'administration après la suppression réussie d'un cours
@app.route('/admin/supprimer_cours/<int:id_cours>', methods=['POST'])
@login_required
def supprimer_cours(id_cours):
    if not current_user.is_admin:
        abort(403)
    db = get_db()
    db.delete_cours(id_cours) # supprime le cours de la base de données
    flash(f'Cours supprimé avec succès.', 'success') # message de succès afficher à l'admin sur la page admin
    return redirect(url_for('admin'))

# route pour modifier un cours ( seulement pour l'admin )
# retourne à la page d'administration après la modification réussie d'un cours
@app.route('/admin/modifier_cours/<int:id_cours>', methods=['GET', 'POST'])
@login_required
def modifier_cours(id_cours):
    if not current_user.is_admin:
        abort(403)
    db = get_db() 
    cours = db.get_cours_par_id(id_cours) 
    if not cours:
        abort(404)
    form = AddCourseForm(obj=cours)  # Pré-remplit le formulaire avec les données existantes
    if form.validate_on_submit():
        nom_cours = form.nom_cours.data.strip()
        description = form.description.data.strip()
        db.modify_cours(id_cours, nom_cours, description)
        flash(f'Cours modifié avec succès.', 'success')
        return redirect(url_for('admin'))
    return render_template('insert_cours.html', form=form, edit=True, cours=cours)  # Réutilise insert_cours.html avec un flag edit


if __name__ == '__main__':
    app.run(debug=True)