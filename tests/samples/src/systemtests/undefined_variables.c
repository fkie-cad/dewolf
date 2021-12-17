#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

int test1(){
    int a, b;
    
    printf("Enter any number: ");
    scanf("%d", &a);
    
    printf("Enter another number: ");
    scanf("%d", &b);
    
    if(a < b){
        printf("Enter a number larger than %d: \n", a);
        scanf("%d", &a);
        a = 2 * a;
        
        
        a = a + 5;
    }
    
    a = a * b;
        
    
    printf("the final number is %d : \n", a);

    return 0;
}


int test2(){
    int n, u;
    
    printf("Enter any number: ");
    scanf("%d", &n);
    
        
    if(n % 2){
        n = n / 2;
        u = n - 1;
    }
    else{
        u = n - 1;
    }
    
    n = n + u;
        
    printf("the final number is %d, &d : \n", n, u);

    return 0;
}

int test3(){
    int a, b;
    
    printf("Enter any number: ");
    scanf("%d", &a);
    
    printf("Enter another number: ");
    scanf("%d", &b);
    
    if(a < b){
        printf("Enter a number larger than %d: \n", a);
        scanf("%d", &a);
    }
    
    a = a * b;
        
    
    printf("the final number is %d : \n", a);

    return 0;
}

int test4(){
    int a, b;
    
    printf("Enter any number: ");
    scanf("%d", &a);
    
    printf("Enter another number: ");
    scanf("%d", &b);
    
    if(a < b){
        scanf("%d", &a);
    }
    
    a = a * b;
        
    
    printf("the final number is %d : \n", a);

    return 0;
}

int test5(){
    int a, b;
    
    printf("Enter any number: ");
    scanf("%d", &a);
    
    printf("Enter another number: ");
    scanf("%d", &b);
    
    if(a < b){
        scanf("%d", &a);
    }
    else{
        scanf("%d", &a);
    }
    
    a = a * b;
        
    
    printf("the final number is %d : \n", a);

    return 0;
}

int test6(){
    int a, b;
    
    printf("Enter any number: ");
    scanf("%d", &a);
    
    printf("Enter another number: ");
    scanf("%d", &b);
    
    if(a < b){
        scanf("%d", &a);
        scanf("%d", &b);
    }
    else{
        scanf("%d", &a);
        scanf("%d", &b);
    }
    
    a = a * b;
        
    
    printf("the final number is %d : \n", a);
    
    
    int c, d;
    
    printf("Enter any number: ");
    scanf("%d", &c);
    
    printf("Enter another number: ");
    scanf("%d", &d);
    
    if(a < b){
        scanf("%d", &c);
        scanf("%d", &d);
    }
    else{
        scanf("%d", &c);
        scanf("%d", &d);
    }
    
    c = c * d;
        
    
    printf("the final number is %d : \n", c);

    return 0;
}


int test7(){
    int a, end;
    
    printf("Enter two a Number:");
    scanf("%d", &end);
    scanf("%d", &a);
    
    for(int i=1; i<=end; i++){
        a = a* i;
        if(a < end){
            scanf("%d", &a);
        }
        else{
            i = end + 1;
        }
    }
    
    if(a < end){
        scanf("%d", &a);
    }
    
    printf("The final number is %d: \n", a);
    
    return 0;
}

int test8(){
    int a, end;
    
    printf("Enter two a Number:");
    scanf("%d", &end);
    scanf("%d", &a);
    
    for(int i=1; i<=end; i++){
        a = a* i;
    }
    
    if(a < end){
        scanf("%d", &a);
    }
    
    printf("The final number is %d: \n", a);
    
    return 0;
}

int test9(){
    int a;
    int b = 12;
    printf("Enter any number: ");
    scanf("%d", &a);
    
        
    if(a < b){
        printf("Enter a number larger than %d: \n", a);
        scanf("%d", &a);
        
        printf("You can add an even larger number than %d: \n", a);
        scanf("%d", &a);
    }
    
    a = a * b;
        
    
    printf("the final number is %d : \n", a);

    return 0;
}

int test10(int y){
    int a;
    int x = 155;
//     int y = rand();
    
        
    if(x < y){
        printf("Enter a number larger than %d: \n", x);
        scanf("%d", &a);
        y = (x+a) / 2;
    }
    else{
        printf("Enter a number smaller than %d: \n", x);
        scanf("%d", &a);
        y = (x+a) /2;
    }
    
    printf("The current number is %d : \n", y);
    
    a = 2 * y;
    
    printf("And the other numer is %d : \n", a);

    return 0;
}

int test11(){
    int a;
    int b = 12;

    scanf("%d", &a);
    
        
    if(a < b){
        printf("Enter a number larger than %d: \n", a);
        scanf("%d", &a);
        
        printf("You can add an even larger number than %d: \n", a);
        scanf("%d", &a);
    }
    
    a = a * b;
        
    
    printf("the final number is %d : \n", a);

    return 0;
}

int test12(){
    int a;
    int x = 155;
    int y = rand();
    
        
    if(x < y){
        printf("Enter a number larger than %d: \n", x);
        scanf("%d", &a);
        y = (x+a) / 2;
    }
    else{
        a = 10;
        y = (x+a) /2;
    }
    
    printf("The current number is %d : \n", y);
    
    a = 2 * y;
    
    printf("And the other numer is %d : \n", a);

    return 0;
}

int test13(){
    int a;
    int x = 155;
    int y = rand();
    
        
    if(x < y){
        a = 12;
        y = (x+a) / 2;
    }
    else{
        a = 10;
        y = (x+a) /2;
    }
    
    printf("The current number is %d : \n", y);
    
    a = 2 * y;
    
    printf("And the other numer is %d : \n", a);

    return 0;
}

int test14(int y){
    int a;
    int x = 155;
    printf("Enter a number\n");
        
    if(x < y){
        scanf("%d", &a);
        y = (x+a) / 2;
    }
    else{
        printf("Enter a number larger than %d: \n", x);
        scanf("%d", &a);
        y = (y+a) /2;
    }
    
    printf("The current number is %d : \n", y);
    
    a = 2 * y;
    
    printf("And the other numer is %d : \n", a);

    return 0;
}

int test15(int y){
    int a = 4;
    int x = 155;
    printf("Enter a number\n");
        
    if(x < y){
        scanf("%d", &a);
        y = (x+a) / 2;
    }
    else{
        printf("Enter a number larger than %d: \n", x);
        scanf("%d", &a);
        y = (y+a) /2;
    }
    
    printf("The current number is %d : \n", y);
    
    a = 2 * y;
    
    printf("And the other numer is %d : \n", a);

    return 0;
}

int test20(){
    int a;
    for(int i=0; i<10; i++){
        a = a+i;
        printf("Numb is %d:\n", a);
    }
    return 0;
}


int main()
{
	test1();
	test2();
    test3();
    test4();
    test5();
    test6();
    test7();
    test8();
    test9();
    test10(50);
    test11();
    test12();
}
