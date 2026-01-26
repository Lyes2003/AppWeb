
create table utilisateurs (
    id_utilisateur INTEGER PRIMARY KEY,
    nom varchar(100) not null,
    courriel varchar(100) not null unique,
    mot_de_passe varchar(255) not null,
    created_at timestamp default current_timestamp
);

create table cours (
    id_cours INTEGER PRIMARY KEY,
    nom_cours varchar(100) not null,
    description text
);

create table chapitres (
    id_chapitre INTEGER PRIMARY KEY,
    id_cours integer references cours(id_cours) on delete cascade,
    titre varchar(100) not null,
    contenu text
);

create table documents (
    id_document INTEGER PRIMARY KEY,
    id_chapitre integer references chapitres(id_chapitre) on delete cascade,
    nom_document varchar(100) not null,
    url_document varchar(255) not null,
    type_document varchar(50) not null
);

insert into utilisateurs (nom, courriel, mot_de_passe) values
('Admin', 'chikhlyes55@gmail.com', 'Lool2003%');