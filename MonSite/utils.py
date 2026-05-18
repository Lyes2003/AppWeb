import re
from flask import g
from flask_login import UserMixin, login_user
from database import Database
from urllib.parse import urlparse, urljoin
from flask import request
from urllib.parse import urlparse, urljoin

#--- User class pour Flask-Login ---
class User(UserMixin):
    def __init__(self, id_utilisateur, nom, courriel, is_admin=False):
        self.id = id_utilisateur
        self.nom = nom
        self.courriel = courriel
        self.is_admin = is_admin

# Database connection management
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        g._database = Database()
    return g._database

# Fonction pour vérifier si une URL est sûre
def is_safe_url(target):
    if not target:
        return False
    host_url = request.host_url
    ref_url = urlparse(host_url)
    test_url = urlparse(urljoin(host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# --- Validation utilities ---
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
NAME_REGEX = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ' \-]{2,100}$")

def is_valid_email(email: str) -> bool:
    if not email:
        return False
    return bool(EMAIL_REGEX.match(email))

def is_valid_name(name: str) -> bool:
    if not name:
        return False
    return bool(NAME_REGEX.match(name.strip()))

def is_strong_password(pw: str):
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