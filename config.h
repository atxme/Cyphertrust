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
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <time.h>
#include <unistd.h>

//system hearder
#include <sys/types.h>
#endif

#define MAX_KEY_LENGTH 32
#define MAX_IV_LENGTH 16
#define MAX_SALT_LENGTH 16
#define MAX_ITERATIONS 100000

#define MAX_USERNAME_LENGTH 32
#define MAX_PASSWORD_LENGTH 99
#define MIN_PASSWORD_LENGTH 6
#define MAX_PASSWORD_ATTEMPTS 3
#define SALT_SIZE 16



