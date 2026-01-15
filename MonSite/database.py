# Copyright 2022 Jacques Berger
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


import sqlite3
    

def _build_utilisateurs(result_set_item):
    utilisateur = {}
    utilisateur["id_utilisateur"] = result_set_item[0]
    utilisateur["nom"] = result_set_item[1]
    utilisateur["courriel"] = result_set_item[2]
    utilisateur["mot_de_passe"] = result_set_item[3]
    utilisateur["created_at"] = result_set_item[4]
    return utilisateur

def _build_cours(result_set_item):
    cours = {}
    cours["id_cours"] = result_set_item[0]
    cours["nom_cours"] = result_set_item[1]
    cours["description"] = result_set_item[2]
    return cours

def _build_chapitres(result_set_item):
    chapitre = {}
    chapitre["id_chapitre"] = result_set_item[0]
    chapitre["id_cours"] = result_set_item[1]
    chapitre["titre"] = result_set_item[2]
    chapitre["contenu"] = result_set_item[3]
    return chapitre

def _build_documents(result_set_item):
    document = {}
    document["id_document"] = result_set_item[0]
    document["id_chapitre"] = result_set_item[1]
    document["nom_document"] = result_set_item[2]
    document["url_document"] = result_set_item[3]
    document["taillee"] = result_set_item[4]
    return document



class Database:
    def __init__(self):
        self.connection = None

    def get_connection(self):
        if self.connection is None:
            self.connection = sqlite3.connect('db/maBase.db')
        return self.connection

    def disconnect(self):
        if self.connection is not None:
            self.connection.close()
    
    def get_utilisateurs(self):
        cursor = self.get_connection().cursor()
        query = ("select id_utilisateur, nom, courriel, mot_de_passe, "
                 "created_at from utilisateurs")
        cursor.execute(query)
        all_data = cursor.fetchall()
        return [_build_utilisateurs(item) for item in all_data]

    def get_utilisateur_par_courriel(self, courriel):
        cursor = self.get_connection().cursor()
        query = ("select id_utilisateur, nom, courriel, mot_de_passe, "
                 "created_at from utilisateurs where courriel = ?")
        cursor.execute(query, (courriel,))
        item = cursor.fetchone()
        if item is None:
            return None
        else:
            return _build_utilisateurs(item)

    def get_cours(self):
        cursor = self.get_connection().cursor()
        query = ("select id_cours, nom_cours, description from cours")
        cursor.execute(query)
        all_data = cursor.fetchall()
        return [_build_cours(item) for item in all_data]

    def get_chapitres(self):
        cursor = self.get_connection().cursor()
        query = ("select id_chapitre, id_cours, titre, contenu from chapitres")
        cursor.execute(query)
        all_data = cursor.fetchall()
        return [_build_chapitres(item) for item in all_data]

    def get_documents(self):
        cursor = self.get_connection().cursor()
        query = ("select id_document, id_chapitre, nom_document, url_document, "
                 "type_document from documents")
        cursor.execute(query)
        all_data = cursor.fetchall()
        return [_build_documents(item) for item in all_data]

    def get_utilisateur(self, utilisateur_id):
        cursor = self.get_connection().cursor()
        query = ("select id_utilisateur, nom, courriel, mot_de_passe, "
                 "created_at from utilisateurs where id_utilisateur = ?")
        cursor.execute(query, (utilisateur_id,))
        item = cursor.fetchone()
        if item is None:
            return item
        else:
            return _build_utilisateurs(item)

    def get_document(self, document_id):
        cursor = self.get_connection().cursor()
        query = ("select id_document, id_chapitre, nom_document, url_document, "
                 "taillee from documents where id_document = ?")
        cursor.execute(query, (document_id,))
        item = cursor.fetchone()
        if item is None:
            return item
        else:
            return _build_documents(item)

    def insert_utilisateur(self, nom, courriel, mot_de_passe):
        connection = self.get_connection()
        query = ("insert into utilisateurs(nom, courriel, mot_de_passe) "
                 "values(?, ?, ?)")
        connection.execute(query, (nom, courriel, mot_de_passe))
        cursor = connection.cursor()
        cursor.execute("select last_insert_rowid()")
        lastId = cursor.fetchone()[0]
        connection.commit()
        return lastId

    def insert_document(self, id_chapitre, nom_document, url_document, type_document):
        connection = self.get_connection()
        query = ("insert into documents(id_chapitre, nom_document, url_document, "
                 "type_document) values(?, ?, ?, ?)")
        connection.execute(query, (id_chapitre, nom_document, url_document,
                                   type_document))
        cursor = connection.cursor()
        cursor.execute("select last_insert_rowid()")
        lastId = cursor.fetchone()[0]
        connection.commit()
        return lastId

    def delete_document(self, document_id):
        connection = self.get_connection()
        query = "delete from documents where id_document = ?"
        connection.execute(query, (document_id,))
        connection.commit()
        return True

# End of database.py
