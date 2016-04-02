#include <string.h>
#include <stdio.h>

void overflow_me(){
    char name[20];
    printf("Welcome.. what is your name?\n");
    read(0, name, 80);
    return;
}

int main(int argc, char** argv){
    char vuln[32];
    printf("Password protected. Enter password:\n");

    read(0, vuln, 32);
    if(strstr(vuln, "badpassword") == vuln)
        overflow_me();
    else
        printf("Wrong password\n");

    return 0;
}
