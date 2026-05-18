from flask import render_template, url_for, redirect, request, flash, abort, current_app, send_file
from flask import Blueprint
from flask_login import login_user, login_required, current_user
from utils import get_db, User, is_safe_url
from forms import DeleteDocumentForm
import os
import random

managdocuments = Blueprint('managdocuments', __name__)

# Route pour afficher les fichiers PDF d'un chapitre d'un cours
# retourne le fichier PDF du document spécifié par son ID
@managdocuments.route('/document/<int:id_document>')
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
    file_path = os.path.join(current_app.root_path, document['url_document'])
    
    # Vérifier que le fichier existe et qu'on n'essaie pas d'accéder hors du dossier uploads/
    real_path = os.path.realpath(file_path)  # Résoudre les ../ et symlinks
    upload_folder_real = os.path.realpath(current_app.config['UPLOAD_FOLDER']) # Chemin réel du dossier uploads
    
    # verifie que le chemain commance bien par le dossier uploads et que le fichier existe
    if not real_path.startswith(upload_folder_real) or not os.path.exists(real_path):
        abort(403)  # Accès refusé
    
    # Servir le fichier
    return send_file(
        real_path,
        as_attachment=False,  # Afficher dans le navigateur 
        mimetype='application/pdf'
    )

# Route pour supprimer un document 
@managdocuments.route('/admin/supprimer_document', methods=['POST'])
@login_required
def supprimer_document():
    if not current_user.is_admin:
        abort(403)
    form = DeleteDocumentForm()
    if form.validate_on_submit():
        id_document = int(form.id_document.data)
        # Récupérer le document depuis la base de données
        db = get_db()
        document = db.get_document(id_document)
        if document:
            # Supprimer le fichier du serveur
            file_path = os.path.join(current_app.root_path, document['url_document'].lstrip('/'))
            if os.path.exists(file_path):
                os.remove(file_path)
            # Supprimer le document de la base de données
            db.delete_document(id_document)
            flash('Document supprimé avec succès.', 'success')
        else:
            flash('Document non trouvé.', 'error')
    return redirect(url_for('admin'))