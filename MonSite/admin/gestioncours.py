from flask import render_template, url_for, redirect, request, flash, abort
from flask import Blueprint
from flask_login import login_user, login_required, current_user
from utils import get_db, User, is_safe_url
from forms import AddCoursForm, DeleteCoursForm, AddChapterForm, RechercheForm, DeleteChapitreForm, DeleteDocumentForm

admin = Blueprint('admin', __name__)

# route pour ajouter un cours ( seulement pour l'admin )
# retourne à la page d'administration après l'ajout réussi d'un cours
@admin.route('/Ajouter_Cours', methods=['GET', 'POST'])
@login_required
def add_cours():
    if not current_user.is_admin:
        abort(403)  # fait echouer la requête si l'utilisateur n'est pas admin
    form = AddCoursForm()
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
@admin.route('/cours/<int:id_cours>')
@login_required
def cours_detail(id_cours):
    db = get_db()
    cours = db.get_cours_par_id(id_cours) # obtenir les détails du cours
    chapitres = db.get_chapitre_par_id_cours(id_cours) # obtenir les chapitres du cours
    if not cours:
        abort(404)
    return render_template('cours_detail.html', cours=cours, chapitres=chapitres)

# route pour modifier un cours ( seulement pour l'admin )
# retourne à la page d'administration après la modification réussie d'un cours
@admin.route('/modifier_cours/<int:id_cours>', methods=['GET', 'POST'])
@login_required
def modifier_cours(id_cours):
    if not current_user.is_admin:
        abort(403)
    db = get_db() 
    cours = db.get_cours_par_id(id_cours) 
    if not cours:
        abort(404)
    form = AddCoursForm(obj=cours)  # Pré-remplit le formulaire avec les données existantes
    if form.validate_on_submit():
        nom_cours = form.nom_cours.data.strip()
        description = form.description.data.strip()
        db.modify_cours(id_cours, nom_cours, description)
        flash(f'Cours modifié avec succès.', 'success')
        return redirect(url_for('admin'))
    return render_template('insert_cours.html', form=form, edit=True, cours=cours) 

# route pour supprimer un cours ( seulement pour l'admin MOI ! )
# supprime aussi tous les chapitres, documents et fichiers associés (suppression récursive)
# retourne à la page d'administration après la suppression réussie d'un cours
@admin.route('/supprimer_cours', methods=['POST'])
@login_required
def supprimer_cours():
    if not current_user.is_admin:
        abort(403)
    form = DeleteCoursForm()
    if form.validate_on_submit():
        id_cours = int(form.id_cours.data)
    if not id_cours:
        flash('Veuillez sélectionner un cours.', 'error')
        return redirect(url_for('admin'))

    db = get_db()
    cours = db.get_cours_par_id(id_cours)

    # si cours n'existe pas on affiche la page 404
    if not cours:
        abort(404) 

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
