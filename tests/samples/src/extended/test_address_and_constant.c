#include <stdio.h>

int is_odd(int numb){
    if ( numb % 2 ){
        return 0;
    }
    else{
        return 1;
    }
}


int test1() {
    int a;
    printf("Enter a positive number \n");
    scanf("%d", &a);
    printf(" numbers from %d to zero : \n", a);
    while(a > 0){
        printf("%d\n", a);
        a = a-2;
        if (is_odd(a)){
            a = a - 1;
        }
    }
    printf("Done \n");
    return 0;
}


int test2(){
    int a;
    printf("Enter a positive number \n");
    scanf("%d", &a);
    
    if(a){
        printf("You chose number %d: \n", a);
    }
    
    if(!a){
        printf("Not a positive integer");
    }
    
    return 0;
}

int test3(int week)
{
    
    switch(week + 2)
    {
        case 1: 
            printf("Monday");
            break;
        case 2: 
            printf("Tuesday");
            break;
        case 3: 
            printf("Wednesday");
            break;
        case 4: 
            printf("Thursday");
            break;
        case 5: 
            printf("Friday");
            break;
        case 6: 
            printf("Saturday");
            break;
        case 7: 
            printf("Sunday");
            break;
        default:
            printf("Invalid input! Please enter week number between 1-7.");
    }

    return 0;

}

int test4()
{

    int iChoice = 0;
    int i;
    int j;
    int a = 0;

    printf("Enter your choice = ");
    scanf( "%d", &iChoice);
    
    printf("Enter a number \n");
    scanf("%d", &i);
    
    printf("Enter a second number \n");
    scanf("%d", &j);

    switch ( iChoice )
    {
        case 1:
            i++;
            a = j * i;
            break;

        case 2:
            i = i + 2;
            a = j + i;
            break;

        case 3:
            i = i + 3;
            a = j - i;
            break;
            
        case 4:
            i = i + 4;
            a =  i - j;
            break;
        
        case 5:
            i = i + 5;
            a = (i-j) * (j-i);
            break;
            
        default:
            printf("default !\n" );
            break;
    }

//     printf("Value of i = %d, Value of j=%d",i, j);
    printf("a = %d \n", a);

    return 0;
}


int mod_pow2(int base, int exp, int modulus){
    if(modulus == 1) return 0;
    int result = 1;
    while(exp > 0){
        if (exp % 2 == 1)  result = (result * base) % modulus;
        exp = exp >> 1;
        base = (base * base) % modulus;
    }
    return result;
}




int main(){
    test1();
}
