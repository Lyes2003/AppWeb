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
from flask import Flask, url_for, render_template, g, request, redirect, session, flash, abort, send_file
from database import Database
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import timedelta
from urllib.parse import urlparse, urljoin
from flask_wtf import CSRFProtect   # import: active CSRF via Flask-WTF
from forms import AddCourseForm, DeleteCourseForm, LoginForm, RegisterForm, AddChapterForm, RechercheForm
from flask_wtf.csrf import CSRFError
from werkzeug.utils import secure_filename


app = Flask(__name__, static_url_path="", static_folder="static")

# Configuration de l'application Flask
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_me_secure_key') # clé secrète pour les sessions et CSRF
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
login_manager.login_view = 'login'

#--- User class pour Flask-Login ---
class User(UserMixin):
    def __init__(self, id_utilisateur, nom, courriel, is_admin=False):
        self.id = id_utilisateur
        self.nom = nom
        self.courriel = courriel
        self.is_admin = is_admin 

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
    form = RechercheForm()
    cours = db.get_cours()
    cours_aleatoire = random.sample(cours, min(9, len(cours))) # Sélectionne jusqu'à 9 cours aléatoires
    return render_template('dashboard.html', nom=current_user.nom, cours=cours_aleatoire, form=form)

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
        if utilisateur and check_password_hash(utilisateur['mot_de_passe'], mot_de_passe):
            user_obj = User(utilisateur['id_utilisateur'], utilisateur['nom'], utilisateur['courriel'], utilisateur['is_admin'])
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
    # Calculer le nombre de chapitres pour chaque cours
    for c in cours:
        c['nbr_chapitres'] = db.count_chapitres_par_cours(c['id_cours'])
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
    cours = db.get_cours_par_id(id_cours) # obtenir les détails du cours
    chapitres = db.get_chapitre_par_id_cours(id_cours) # obtenir les chapitres du cours
    if not cours:
        abort(404)
    return render_template('cours_detail.html', cours=cours, chapitres=chapitres)

# Route pour afficher les chapitres d'un cours
# retourne la page des chapitres du cours spécifié par son ID
@app.route('/cours/<int:id_cours>/chapitres')
@login_required
def chapitres_cours(id_cours):
    db = get_db()
    chapitres = db.get_chapitre_par_id_cours(id_cours) # obtenir les chapitres du cours    
    return render_template('chapitres.html', chapitres=chapitres, id_cours=id_cours)

@app.route('/cours/<int:id_cours>/chapitre/ajouter', methods=['GET', 'POST'])
@login_required
def ajouter_chapitre(id_cours):
    if not current_user.is_admin:
        abort(403)
    db = get_db()
    form = AddChapterForm()
    if form.validate_on_submit():
        nom_chapitre = form.nom_chapitre.data.strip()
        description = form.description.data.strip()

        id_chapitre = db.insert_chapitre(id_cours, nom_chapitre, description)
        nbr_chapitres = db.count_chapitres_par_cours(id_cours)

        # Gérer le téléchargement du fichier PDF
        if form.pdf.data: # un fichier a été téléchargé
            pdf_file = form.pdf.data
            filename = secure_filename(pdf_file.filename) # sécurise le nom du fichier
            unique_name = f"random_{random.randint(100000, 999999)}_{filename}" # nom unique pour éviter les collisions 
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name) # chemin complet du fichier
            pdf_file.save(file_path) # sauvegarde le fichier sur le serveur
            # Stocker le chemin relatif 
            url_document = f"uploads/{unique_name}"
            # Enregistrer le document dans la base de données
            db.insert_document(id_chapitre, filename, url_document, 'pdf') 

        flash(f'Le chapitre "{nom_chapitre}" a été ajouté avec succès.', 'success')
        return redirect(url_for('chapitres_cours', id_cours=id_cours))
    return render_template('insert_chapitre.html', form=form, id_cours=id_cours)

# Route pour afficher les détails d'un chapitre d'un cours
# retourne la page de détails du chapitre spécifié par son ID et l'ID du cours
@app.route('/cours/<int:id_cours>/chapitre/<int:id_chapitre>')
@login_required
def chapitre_detail(id_cours, id_chapitre):
    db = get_db()
    chapitre = db.get_chapitre_par_id(id_chapitre)
    if not chapitre or chapitre['id_cours'] != id_cours: # vérifie que le chapitre appartient au cours
        abort(404)
    documents = db.get_documents_par_chapitre(id_chapitre) # obtenir les documents du chapitre
    return render_template('chapitre_detail.html', chapitre=chapitre, documents=documents)

# Route pour afficher les fichiers PDF d'un chapitre d'un cours
# retourne le fichier PDF du document spécifié par son ID
@app.route('/document/<int:id_document>')
@login_required
def serve_document(id_document):
    
    # Récupérer le document depuis la base de données et vérifier les droits d'accès 
    # avec le chapitre et le cours associés
    
    # initialize la base de données
    db = get_db()
    document = db.get_document(id_document)
    
    # Vérifier que le document existe
    if not document:
        abort(404)
    
    # Récupérer le chapitre pour vérifier les droits
    chapitre = db.get_chapitre_par_id(document['id_chapitre'])
    
    # Vérifier que le chapitre existe
    if not chapitre:
        abort(404)
    
    
    # Construire le chemin du fichier
    # Contient le chemin du fichier stocké avec son nom
    file_path = os.path.join(app.root_path, document['url_document'])
    
    # Vérifier que le fichier existe et qu'on n'essaie pas d'accéder hors du dossier uploads/
    real_path = os.path.realpath(file_path)  # Résoudre les ../ et symlinks
    upload_folder_real = os.path.realpath(app.config['UPLOAD_FOLDER']) # Chemin réel du dossier uploads
    
    # verifie que le chemain commance bien par le dossier uploads et que le fichier existe
    if not real_path.startswith(upload_folder_real) or not os.path.exists(real_path):
        abort(403)  # Accès refusé
    
    # Servir le fichier
    return send_file(
        real_path,
        as_attachment=False,  # Afficher dans le navigateur 
        mimetype='application/pdf'
    )

# route pour supprimer un cours ( seulement pour l'admin )
# supprime aussi tous les chapitres, documents et fichiers associés (suppression récursive)
# retourne à la page d'administration après la suppression réussie d'un cours
@app.route('/admin/supprimer_cours/<int:id_cours>', methods=['POST'])
@login_required
def supprimer_cours(id_cours):
    if not current_user.is_admin:
        abort(403)
    db = get_db()

    # Récupérer tous les chapitres du cours
    chapitres = db.get_chapitre_par_id_cours(id_cours)

    # Pour chaque chapitre on supprime les documents associés
    for chapitre in chapitres:
        documents = db.get_documents_par_chapitre(chapitre['id_chapitre'])
        # Supprimer les fichiers PDF du serveur
        for doc in documents:
            file_path = os.path.join(app.root_path, doc['url_document'].lstrip('/')) # Chemin complet du fichier
            if os.path.exists(file_path):
                os.remove(file_path)  # Supprime le fichier du serveur
            db.delete_document(doc['id_document'])  # Supprime le document de la BDD
        # Supprimer le chapitre
        db.delete_chapitre(chapitre['id_chapitre'])
    
    # Supprimer le cours
    db.delete_cours(id_cours)
    flash(f'Cours supprimé avec succès (avec tous ses chapitres et documents).', 'success')
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

@app.route('/recherche', methods=['POST'])  
@login_required
def recherche():
    form = RechercheForm() # crée le formulaire
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
    app.run(debug=True)