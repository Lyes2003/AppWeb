from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo

# Formulaire de connexion et d'enregistrement avec validation
class LoginForm(FlaskForm):
    courriel = StringField('Courriel', validators=[DataRequired(), Email(), Length(max=25)]) # Courriel limité à 25 caractères
    mot_de_passe = PasswordField('Mot de passe', validators=[DataRequired()]) # Mot de passe obligatoire
    remember = BooleanField('Se souvenir de moi') # Case à cocher pour "se souvenir de moi"
    submit = SubmitField('Se connecter') # Bouton de soumission

# Formulaire d'enregistrement avec validation des champs et confirmation du mot de passe
class RegisterForm(FlaskForm):
    nom = StringField('Nom', validators=[DataRequired(), Length(max=25)]) # Nom limité à 25 caractères
    courriel = StringField('Courriel', validators=[DataRequired(), Email(), Length(max=25)]) # Courriel limité à 25 caractères
    mot_de_passe = PasswordField('Mot de passe', validators=[DataRequired()]) # Mot de passe obligatoire
    mot_de_passe_confirm = PasswordField('Confirmer', validators=[DataRequired(), EqualTo('mot_de_passe')]) # Confirmation du mot de passe
    submit = SubmitField("S'enregistrer")