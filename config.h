#ifndef PACKAGES_CONFIG_H
#define PACKAGES_CONFIG_H

//openssl headers
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

//sqlite3 headers
#include <sqlite3.h>

//c++ headers
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <time.h>
#include <unistd.h>
#include <filesystem>
#include <termios.h>

//system hearder
#include <sys/types.h>
#include <secret.h>
#endif

extern bool connected;

#define MAX_KEY_LENGTH 32
#define MAX_IV_LENGTH 16
#define MAX_SALT_LENGTH 16
#define MAX_ITERATIONS 100000

#define MAX_USERNAME_LENGTH 32
#define MAX_PASSWORD_LENGTH 64
#define MIN_PASSWORD_LENGTH 6
#define MIN_USERNAME_LENGTH 6
#define MAX_PASSWORD_ATTEMPTS 3
#define SALT_SIZE 16
#define ID_USER_MAX_LENGHT 96

#define APP_DIRECTORY "/home/christophe/.cypher"



