# ce fichier définit les formulaires de connexion et d'enregistrement utilisés dans l'application Flask

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_wtf.file import FileField, FileAllowed

# Formulaire de connexion et d'enregistrement avec validation
class LoginForm(FlaskForm):
    courriel = StringField('Courriel', validators=[DataRequired(), Email(), Length(max=25, min=6)]) # Courriel limité à 25 caractères
    mot_de_passe = PasswordField('Mot de passe', validators=[DataRequired()]) # Mot de passe obligatoire
    remember = BooleanField('Se souvenir de moi') # Case à cocher pour "se souvenir de moi"
    submit = SubmitField('Se connecter') # Bouton de soumission

# Formulaire d'enregistrement avec validation des champs et confirmation du mot de passe
class RegisterForm(FlaskForm):
    nom = StringField('Nom', validators=[DataRequired(), Length(max=25)]) # Nom limité à 25 caractères
    courriel = StringField('Courriel', validators=[DataRequired(), Email(), Length(max=25, min=6)]) # Courriel limité à 25 caractères
    mot_de_passe = PasswordField('Mot de passe', validators=[DataRequired()]) # Mot de passe obligatoire
    mot_de_passe_confirm = PasswordField('Confirmer', validators=[DataRequired(), EqualTo('mot_de_passe')]) # Confirmation du mot de passe
    submit = SubmitField("S'enregistrer") # Bouton de soumission

# Formulaire pour admin pour ajouter un cours
class AddCourseForm(FlaskForm):
    nom_cours = StringField('Nom du cours', validators=[DataRequired(), Length(max=100)]) # Nom du cours limité à 100 caractères
    description = StringField('Description', validators=[DataRequired(), Length(max=255)]) # Description limitée à 255 caractères
    submit = SubmitField('Ajouter le cours') # Bouton de soumission

# Formulaire pour admin pour supprimer un cours
class DeleteCourseForm(FlaskForm):
    cours_id = StringField('ID du cours', validators=[DataRequired()]) # ID du cours obligatoire
    submit = SubmitField('Supprimer le cours') # Bouton de soumission

# Formulaire pour admin pour ajouter un chapitre
class AddChapterForm(FlaskForm):
    nom_chapitre = StringField('Nom du chapitre', validators=[DataRequired(), Length(max=100)]) # Nom du chapitre limité à 100 caractères
    description = StringField('Description', validators=[DataRequired(), Length(max=255)]) # Description limitée à 255 caractères
    pdf = FileField('Document PDF', validators=[FileAllowed(['pdf'], 'Seuls les fichiers PDF sont autorisés.')]) # Champ pour télécharger un fichier PDF
    submit = SubmitField('Ajouter le chapitre') # Bouton de soumission