#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

#define MAX 1024

// @code by gil_cedrick can be use for free gpl
// MD5 HASH : input file_Plaintext -> file_Hash_MD5

void calculate_md5(const char *input, char *md5_result) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;

    OpenSSL_add_all_algorithms();

    md = EVP_get_digestbyname("md5");
    if (!md) {
        fprintf(stderr, "MD5 not supported!\n");
        exit(EXIT_FAILURE);
    }

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, strlen(input));
    EVP_DigestFinal_ex(mdctx, md5_result, NULL);
    EVP_MD_CTX_free(mdctx);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Utilisation : %s <file_plaintext_input> <file_hash_output>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *file = fopen(argv[1], "r");
    FILE *hashFile = fopen(argv[2], "a"); // "a" pour ajouter à la fin du fichier

    if (file == NULL || hashFile == NULL) {
        fprintf(stderr, "Erreur lors de l'ouverture des fichiers.\n");
        return EXIT_FAILURE;
    }

    char *line = (char *)malloc(MAX * sizeof(char));
    size_t len = 0;

    while (getline(&line, &len, file) != -1) {
        // Supprimer le caractère de retour à la ligne à la fin de la ligne
        line[strcspn(line, "\n")] = '\0';

        // Calculer le MD5
        char md5_result[MD5_DIGEST_LENGTH];
        calculate_md5(line, md5_result);

        // Afficher le résultat
//        printf("Ligne : %s\nMD5 : ", line);
  //      for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    //        printf("%02x", (unsigned char)md5_result[i]);
      //  }
       // printf("\n");

        // Écrire le résultat dans le fichier de hachage avec fprintf

        fprintf(hashFile, "%02x", (unsigned char)md5_result[0]);
        for (int i = 1; i < MD5_DIGEST_LENGTH; i++) {
            fprintf(hashFile, "%02x", (unsigned char)md5_result[i]);
        }
        fprintf(hashFile, "\n");  // Ajouter un retour à la ligne après chaque hachage
    }

    free(line);
    fclose(file);
    fclose(hashFile);

    return 0;
}
