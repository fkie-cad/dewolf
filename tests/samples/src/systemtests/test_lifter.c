#include <stdio.h>

int test1() {
    float f;
    printf("Enter a number: ");
    scanf("%f", &f);
    printf("You entered %f, and here's an extra number %f\n", f, 1.2345);
}

int main() {
    test1();
}
