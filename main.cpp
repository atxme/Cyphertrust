#include "config.h"

int main (int argc, char *argv[]){

    if (argc < 2){
        std::cout << "required more than 1 argument" << std::endl;
        return 1;
    }
    bool isUser;
    connected=False;
    while ( connected !=True ){

        isUser = verifyUserData();
        if (!isUser){
            createUser();
        }

        else {
            free(isUser);
            connected = true;
        }

    }
}
