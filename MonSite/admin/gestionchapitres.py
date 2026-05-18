from flask import render_template, url_for, redirect, request, flash, abort, current_app
from flask import Blueprint
from flask_login import login_user, login_required, current_user
from werkzeug.utils import secure_filename
from utils import get_db, User, is_safe_url
from forms import AddChapterForm, DeleteChapitreForm
import os
import random

managchapters =  Blueprint('managchapters', __name__)


# route pour ajouter un chapitre
# retourne la page des chapitres
@managchapters.route('/cours/<int:id_cours>/chapitre/ajouter', methods=['GET', 'POST'])
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
            if pdf_file.filename: # s'assurer qu'un fichier a été sélectionné
                filename = secure_filename(pdf_file.filename) # sécurise le nom du fichier
                unique_name = f"random_{random.randint(100000, 999999)}_{filename}" # nom unique pour éviter les collisions 
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_name) # chemin complet du fichier
                pdf_file.save(file_path) # sauvegarde le fichier sur le serveur
                # Stocker le chemin relatif 
                url_document = f"uploads/{unique_name}"
                # Enregistrer le document dans la base de données
                db.insert_document(id_chapitre, filename, url_document, 'pdf') 

        flash(f'Le chapitre "{nom_chapitre}" a été ajouté avec succès.', 'success')
        return redirect(url_for('managchapters.chapitres_cours', id_cours=id_cours))
    return render_template('insert_chapitre.html', form=form, id_cours=id_cours)


# Route pour afficher les détails d'un chapitre d'un cours
# retourne la page de détails du chapitre spécifié par son ID et l'ID du cours
@managchapters.route('/cours/<int:id_cours>/chapitre/<int:id_chapitre>')
@login_required
def chapitre_detail(id_cours, id_chapitre):
    db = get_db()
    chapitre = db.get_chapitre_par_id(id_chapitre)
    if not chapitre or chapitre['id_cours'] != id_cours: # vérifie que le chapitre appartient au cours
        abort(404)
    documents = db.get_documents_par_chapitre(id_chapitre) # obtenir les documents du chapitre
    return render_template('chapitre_detail.html', chapitre=chapitre, documents=documents)

# Route pour supprimer un chapitre
# retoutne la page d'administration apres la suppretion d'un chapitre
@managchapters.route('/admin/supprimer_chapitre', methods=['POST'])
@login_required
def supprimer_chapitre():
    if not current_user.is_admin: 
        abort(403)
    form = DeleteChapitreForm()
    id_cours = None # initier l'id du cours pour eviter les erreurs de validation
    id_chapitre = None # 

    if form.validate_on_submit():
        id_cours = int(form.id_cours.data)
        id_chapitre = int(form.id_chapitre.data)
    if not id_cours or not id_chapitre:
        flash('Veuillez sélectionner un cours et un chapitre.', 'error')
        return redirect(url_for('admin'))
    
    db = get_db() 
    cours = db.get_cours_par_id(id_cours) 
    chapitre = db.get_chapitre_par_id(id_chapitre)
    documents = db.get_documents_par_chapitre(id_chapitre)
    if not chapitre or  chapitre['id_cours'] != id_cours: 
        abort(404)

    # supprimer les fichires PDF du serveur
    for doc in documents:
        file_path = os.path.join(current_app.root_path, doc['url_document'].lstrip('/')) # Chemin complet du fichier
        if os.path.exists(file_path):
            os.remove(file_path)  # Supprime le fichier du serveur
        db.delete_document(doc['id_document'])  # Supprime le document de la BDD
    # Supprimer le chapitre
    db.delete_chapitre(chapitre['id_chapitre']) 

    flash(f'Chapitre supprimé avec succès (et documents associés).', 'success')
    return redirect(url_for('admin'))

# Route pour afficher les chapitres d'un cours
# retourne la page des chapitres du cours spécifié par son ID
@managchapters.route('/cours/<int:id_cours>/chapitres')
@login_required
def chapitres_cours(id_cours):
    db = get_db()
    chapitres = db.get_chapitre_par_id_cours(id_cours) # obtenir les chapitres du cours    
    return render_template('chapitres.html', chapitres=chapitres, id_cours=id_cours)