#include "config.h"
#include "crypto.hpp"

#define HASH_SIZE 32
#define HASH_PATH "/home/christophe/.cypher/hash.txt"


bool verifyUserData(){
    std::ifstream file(HASH_PATH);  
    if (file.is_open()){
        file.close();
        return true;
    }
    return false;
}


void readPassword(char *password, int max_length) {
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);  // récupère les paramètres actuels du terminal
    newt = oldt;
    newt.c_lflag &= ~ECHO;  // désactive ECHO
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);  // applique les nouveaux paramètres

    // Lisez le mot de passe
    fgets(password, max_length, stdin);
    password[strcspn(password, "\n")] = 0;  // Supprimer le saut de ligne ajouté par fgets

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);  // restaure les paramètres originaux du terminal
}


void lockFile(bool* status) {
    *status =true;
    std::error_code ec;
    std::filesystem::chmod(APP_DIRECTORY, 0700, ec);
    if (ec) {
        std::cout << "Erreur lors du changement des autorisations du dossier : " << ec.message() << std::endl;
        *status = false;
        return;
    }
    std::filesystem::chmod(HASH_PATH, 0400, ec);
    if (ec) {
        std::cout << "Erreur lors du changement des autorisations du fichier : " << ec.message() << std::endl;
        *status = false;
        return;
    }
}


void createUser(bool* status) {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    printf("Please remember your username and password\n");

    std::filesystem::create_directory(APP_DIRECTORY);

    while (true) {

        printf("Username: ");
        scanf("%s", username);
        printf("Password: ");   
        readPassword(password, MAX_PASSWORD_LENGTH); 
        if (strlen(username) < MIN_USERNAME_LENGTH) {
            printf("Username must be at least %d characters long\n", MIN_USERNAME_LENGTH);
        } 
        else if (strlen(password) < MIN_PASSWORD_LENGTH) {
            printf("Password must be at least %d characters long\n", MIN_PASSWORD_LENGTH);
        } 
        else {
            printf("Informations have been collected\n")
            break;
        }
    }

    char hash[HASH_SIZE];
    char idUser[ID_USER_MAX_LENGHT];
    strcpy(idUser, username);
    strcat(idUser, password);

    crypto::SHA512::encrypt(idUser, hash);
    std::ofstream file;
    file.open(HASH_PATH);

    if (file.is_open()) {
        file << hash;
        file.close();

        std::string path_to_database = APP_DIRECTORY + "/database.db";
        std::ofstream file(path_to_database, std::ofstream::out | std::ofstream::trunc);

        if (file.is_open()) {
        file.close();
        }
    }
    else {
        printf("Error could not create user")
    }
    lockFile(status);
    if (status == true ){
        printf("User created succesfully\n")
    }
    else {
        printf("Error with user creation\n")
    }

}

void connectUser(bool * status){
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    printf("Connection environnement started \n");

    for (int i=0 ; i<MAX_PASSWORD_ATTEMPTS ; i++){

        while (true){
            printf("Username: ");
            scanf("%s", username);
            printf("Password: ");   
            readPassword(password, MAX_PASSWORD_LENGTH);
            if (strlen(username) < MIN_USERNAME_LENGTH) {
                printf("Username must be at least %d characters long\n", MIN_USERNAME_LENGTH);
            } 
            else if (strlen(password) < MIN_PASSWORD_LENGTH) {
                printf("Password must be at least %d characters long\n", MIN_PASSWORD_LENGTH);
            } 
            else {
                printf("Informations have been collected\n")
                break;
            }
        }

        char hash[HASH_SIZE];
        char referenceHash[HASH_SIZE];
        char idUser[ID_USER_MAX_LENGHT];
        strcpy(idUser, username);
        strcat(idUser, password);
        std::ifstream file(HASH_PATH);
        file.read(referenceHash, HASH_SIZE);
        file.close();
        crypto::SHA512::encrypt(idUser,hash);
        
        connected = (hash.c_str()==referenceHash.c_str()) ? true : false ;
        if (connected == true ){
            *status =true ;
            return;
        }
        else {
            printf("Acces denied\n");
        }
    }

}