#include <string.h>
#include <stdio.h>

static char *PASSWORD = "\x08\x15\x11\x19#N#\x0f\x13\x10\n\x19#\x1d\x10\x10#\x08\x14\x19#\x08\x14\x15\x12\x1b\x0fv";
static char *KEY = "symexec";

int decrypt_password(char* input){
    int input_len = 0;
    int key_len = 7;
    int i = 0;
    int j = 0;
    input_len = strlen(input);

    for(i = 0; i < input_len; i++){
        for(j = 0; j < key_len; j++){
            input[i] ^= KEY[j];
        }
    }

    if(strcmp(input, PASSWORD) == 0)
        return 1;
    else
        return 0;
}

void overflow_me(){
    char name[20];
    printf("Welcome.. what is your name?\n");
    read(0, name, 80);
    return;
}

int main(int argc, char** argv){
    char pass[32];
    printf("Password protected. Enter password:\n");

    read(0, pass, 32);
    if(decrypt_password(pass))
        overflow_me();
    else
        printf("Wrong password\n");

    return 0;
}
