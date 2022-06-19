#include <mhash.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//execute ldconfig if error while loading shared libraries: libmhash.so.2: cannot open shared object file: No such file or directory
int main(void) {

    //FILE *hashes;
    //hashes = fopen("/home/kassu&infosec/hashes.txt", "r");
    //char** hashsalt;

    FILE *fp;
    fp = fopen("/home/kassu/infosec/words.txt", "r");

    char buffer[3];
    char *b = &buffer;
    char current_word[101];
    memset(current_word, 0, 101 * sizeof(char));
    int c;
    char hash_material[300];
    char* salt1 = "potPlantSalt";
    char* salt2 = "a069cf1409cedc04";
    char hash32[32] = "8337e11c64564faf8782d70590374bc4";

    //c = getc(fp);
    int j = 0; // numbering for printing the current hash
    while (c != EOF) {
        MHASH td;
        td = mhash_init(MHASH_SHA256);
        if (td == MHASH_FAILED) {
            fclose(fp);
            exit(1);
        }
        unsigned char hash[65];
        unsigned char hash_hex[65];

        int n = 0;
        /*while (c != '\n' && n < 100) {
            current_word[n] = c;
            n++;
            c = getc(fp);
        }*/
        fgets(current_word, 100, fp);
        current_word[strlen(current_word)-1] = '\0';
        //printf("%s\n", current_word); //print the current candidate password
        strcpy(hash_material, salt1); //first salt, potPlantSalt
        strcat(hash_material, current_word); //current candidate
        strcat(hash_material, salt2); //second salt
        mhash(td, &hash_material, strlen(salt1) + strlen(current_word) + strlen(salt2)); //salt1 length + username length + salt2 length
        mhash_deinit(td, hash);

        hash_material[0] = '\0'; //end string

        printf("Hash%d : ", j); //print counter
        j++;

        for (int i = 0; i < mhash_get_block_size(MHASH_SHA256); i++) {
            printf("%.2x", hash[i]);
            sprintf(b, "%.2x", hash[i]); //transform hash to hex
            strncat(hash_hex, b, 2);        //split to single hex numbers
        }
        printf("\n");

        if (strncmp(hash32, hash_hex, 10) == 0) {
            printf("found\n");
            printf("%s", current_word);
            fclose(fp);
            exit(0);

        }
        hash_hex[0] = '\0'; //init hash_hex
        memset(current_word, 0, 101 * sizeof(char));
        c = getc(fp);
    }


    fclose(fp);
    exit(0);
}
