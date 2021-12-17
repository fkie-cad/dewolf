#include <stdio.h>

#define loop(X) for(int i=1; i <= 100; i++) { if(i % X == 1) continue; else printf("%d\n", i);}

int main() {
    loop(2);
    loop(3);
    loop(5);
    loop(7);
    loop(11);
    loop(13);
    loop(17);
    loop(19);
}
