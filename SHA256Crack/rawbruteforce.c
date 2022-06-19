#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mhash.h>
//charset for the bruteforcing
static const char alphabet[] =
        "abcdefghijklmnopqrstuvwxyz";
        //"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        //"0123456789"

static const int alphabetSize = sizeof(alphabet) - 1;
int j = 0; //number of hash
void bruteImpl(char* str, int index, int maxDepth)
{
    for (int i = 0; i < alphabetSize; ++i)
    {
        str[index] = alphabet[i];

        if (index == maxDepth - 1) {
            //printf("%s\n", str);
            char buffer[3];
            char *b = &buffer;
            char current_word[101];
            memset(current_word, 0, 101 * sizeof(char));
            char hash_material[300];
            char* salt1 = "potPlantSalt";
            char* salt2 = "a069cf1409cedc04";
            char hash32[32] = "b6e56d624a06f032fd3a13e67af5b608"; //the hash we want to crack in hex format (64 chars truncated to 32 chars)

                MHASH td;
                td = mhash_init(MHASH_SHA256);
                if (td == MHASH_FAILED) {
                    exit(1);
                }
                unsigned char hash[65];
                unsigned char hash_hex[65];
                sprintf(current_word, "%s", str);
                printf("%s\n", current_word);
                strcpy(hash_material, salt1); //first salt
                strcat(hash_material, current_word); //current word from dict
                strcat(hash_material, salt2); //second salt
                //printf("%s\n", hash_material);
                mhash(td, &hash_material, strlen(salt1) + strlen(current_word) + strlen(salt2)); //salt1 length + username length + salt2 length
                mhash_deinit(td, hash);

                hash_material[0] = '\0'; //end string

                printf("Hash%d : ", j);
                j++;

                for (int i = 0; i < mhash_get_block_size(MHASH_SHA256); i++) {
                    printf("%.2x", hash[i]);
                    sprintf(b, "%.2x", hash[i]); // muutetaan hash heksadesimaaliksi
                    strncat(hash_hex, b, 2);        // täytyy lähetää yhden heksadesimaalilivun eli tavun osissa
                }
                printf("\n");

                if (strncmp(hash32, hash_hex, 10) == 0) {
                    printf("found\n");
                    printf("%s", current_word);
                    //fclose(fp);
                    exit(0);

                }
                hash_hex[0] = '\0'; //init hash_hex
                memset(current_word, 0, 101 * sizeof(char));
                //c = getc(fp);
        }
        else bruteImpl(str, index + 1, maxDepth);
    }
}

void bruteSequential(int maxLen)
{
    char* buf = malloc(maxLen + 1);

    for (int i = 1; i <= maxLen; ++i)
    {
        memset(buf, 0, maxLen + 1);
        bruteImpl(buf, 0, i);
    }

    free(buf);
}

int main(void)
{
    bruteSequential(3); //maxLen=max password length to be searched
    exit(0);
}
