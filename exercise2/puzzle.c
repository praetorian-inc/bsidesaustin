#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint8_t Blue, Green, Ivory, Red, Yellow, Englishman, Japanese, Norwegian,
    Spaniard, Ukrainian, Coffee, Milk, OrangeJuice, Tea, Water, Chesterfield,
    Kools, LuckyStrike, OldGold, Parliament, Dog, Fox, Horse, Snails, Zebra;

void print() {
    printf("%d:Blue\n", Blue);
    printf("%d:Green\n", Green);
    printf("%d:Ivory\n", Ivory);
    printf("%d:Red\n", Red);
    printf("%d:Yellow\n", Yellow);
    printf("%d:Englishman\n", Englishman);
    printf("%d:Japanese\n", Japanese);
    printf("%d:Norwegian\n", Norwegian);
    printf("%d:Spaniard\n", Spaniard);
    printf("%d:Ukrainian\n", Ukrainian);
    printf("%d:Coffee\n", Coffee);
    printf("%d:Milk\n", Milk);
    printf("%d:OrangeJuice\n", OrangeJuice);
    printf("%d:Tea\n", Tea);
    printf("%d:Water\n", Water);
    printf("%d:Chesterfield\n", Chesterfield);
    printf("%d:Kools\n", Kools);
    printf("%d:LuckyStrike\n", LuckyStrike);
    printf("%d:OldGold\n", OldGold);
    printf("%d:Parliament\n", Parliament);
    printf("%d:Dog\n", Dog);
    printf("%d:Fox\n", Fox);
    printf("%d:Horse\n", Horse);
    printf("%d:Snails\n", Snails);
    printf("%d:Zebra\n", Zebra);
}

void win() {
    puts("congratulations!");
    exit(0);
}

void fail() {
    puts("womp womp... try again");
    exit(1);
}

int main() {
    char buf[25];
    memset(buf, 0, 25);
    size_t s = read(0, buf, 25);
    size_t i = 0;
    Blue         = buf[i++];
    Green        = buf[i++];
    Ivory        = buf[i++];
    Red          = buf[i++];
    Yellow       = buf[i++];
    Englishman   = buf[i++];
    Japanese     = buf[i++];
    Norwegian    = buf[i++];
    Spaniard     = buf[i++];
    Ukrainian    = buf[i++];
    Coffee       = buf[i++];
    Milk         = buf[i++];
    OrangeJuice  = buf[i++];
    Tea          = buf[i++];
    Water        = buf[i++];
    Chesterfield = buf[i++];
    Kools        = buf[i++];
    LuckyStrike  = buf[i++];
    OldGold      = buf[i++];
    Parliament   = buf[i++];
    Dog          = buf[i++];
    Fox          = buf[i++];
    Horse        = buf[i++];
    Snails       = buf[i++];
    Zebra        = buf[i++];
    print();

    if ((((1<<Blue)|(1<<Green)|(1<<Ivory)|(1<<Red)|(1<<Yellow)) != 0x3e)
     || (((1<<Englishman)|(1<<Japanese)|(1<<Norwegian)|(1<<Spaniard)|(1<<Ukrainian)) != 0x3e)
     || (((1<<Coffee)|(1<<Milk)|(1<<OrangeJuice)|(1<<Tea)|(1<<Water)) != 0x3e)
     || (((1<<Chesterfield)|(1<<Kools)|(1<<LuckyStrike)|(1<<OldGold)|(1<<Parliament)) != 0x3e)
     || (((1<<Dog)|(1<<Fox)|(1<<Horse)|(1<<Snails)|(1<<Zebra)) != 0x3e)) {
        fail();
    }

    if ((Englishman==Red)
     && (Spaniard==Dog)
     && (Coffee==Green)
     && (Ukrainian==Tea)
     && (Green==Ivory+1)
     && (OldGold==Snails)
     && (Kools==Yellow)
     && (Milk==3)
     && (Norwegian==1)
     && ((Chesterfield==Fox+1) || (Chesterfield==Fox-1))
     && ((Kools==Horse+1) || (Kools==Horse-1))
     && (LuckyStrike==OrangeJuice)
     && (Japanese==Parliament)
     && ((Norwegian==Blue+1) || (Norwegian==Blue-1))) {
        win();
    } else {
        fail();
    }
}

