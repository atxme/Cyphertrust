#! #! /bin/bash 


file_path="/home/christophe/.cypher/hash.txt"
path_cypher="/home/christophe/Documents/ESEO/CypherTrust"


if [ ! -f "$file_path" ]; then
    # Créer le fichier s'il n'existe pas
    touch "$file_path"

    "$path_cypher/Cypher"
    
    # Définir les permissions du fichier en lecture seulement pour l'utilisateur propriétaire
    chmod 400 "$file_path"
    parent_dir=$(dirname "$file_path")
    chmod 700 "$parent_dir"
fi

