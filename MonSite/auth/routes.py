from flask import render_template, url_for, redirect, request
from flask import Blueprint
from flask_login import login_user
from forms import LoginForm, RegisterForm
from werkzeug.security import generate_password_hash, check_password_hash
from utils import get_db, User, is_valid_email, is_valid_name, is_strong_password, is_safe_url


auth = Blueprint('auth', __name__)


# Route pour la page de connexion
# retourne à la page d'accueil après une connexion réussie, sinon reste sur la page de connexion avec un message d'erreur
@auth.route('/login', methods=['GET', 'POST'])
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

# Route pour la page d'inscription
# retourne à la page d'accueil après une inscription réussie, sinon reste sur la page d'inscription avec un message d'erreur
@auth.route('/register', methods=['GET', 'POST'])
def register():
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