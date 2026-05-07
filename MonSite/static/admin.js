/* cette fonction permet de gérer les changements de chapitre
 * elle met à jour les options du select des documents en fonction du chapitre sélectionné
 */
(function() {
    const chapitres = window.chapitres; // Récupère depuis le template
    const documents = window.documents; // Récupère depuis le template

    const docsByChapter = {};

    // Regroupe les documents par chapitre
    documents.forEach(d => {
    if (!docsByChapter[d.id_chapitre]) {
        docsByChapter[d.id_chapitre] = []; // Initialise la liste des documents pour ce chapitre
    }
    docsByChapter[d.id_chapitre].push(d); // Ajoute le document à la liste du chapitre
    });

    // permet de gérer les changements de chapitre
    document.querySelectorAll('.chapter-select').forEach(select => {
    const courseId = select.id.replace('chapter-', '');
    const countSpan = document.getElementById(`doc-count-${courseId}`); // Récupère le span pour le compteur de documents
    const docSelect = document.getElementById(`doc-select-${courseId}`); // Récupère le select pour les documents

    // Fonction pour mettre à jour les options du select des documents
    function update(chapitreId) {
        const docs = docsByChapter[chapitreId] || [];
        countSpan.textContent = docs.length; // Met à jour le compteur de documents
        docSelect.innerHTML = docs // Met à jour la liste des documents
        .map(d => `<option value="${d.id_document}">${d.nom_document}</option>`) // Crée les options pour chaque document
        .join(''); // Joint les options en une seule chaîne pour assembler toutes les options en un bloc HTML
    }

    select.addEventListener('change', () => update(select.value));
    update(select.value); // Met à jour les options au chargement de la page
    });
}());