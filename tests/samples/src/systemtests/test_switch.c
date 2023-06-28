#include <stdio.h>
#include <stdlib.h>

int test0(int a, int b)
{
    for(int i = 0; i < 10; i++){
        switch(a){
            case 1:
                printf("You chose the 1\n");
                break;
            case 2:
                printf("You chose the prime number 2\n");
            case 4:
                printf("You chose an even number\n");
                break;
            case 5:
               if( b == 5){
                   goto L;
               }
               printf("both numbers are 5\n");
               break;
            case 3:
                printf("Another prime\n");
                break;
            default:
                printf("Number not between 1 and 5\n");
                if(a > 5){
                    a -= 5;
                }
                else{
                    a += 5;
                }

        }
        b += i;
        printf("b= %d\n", b);
    }
    L: printf("final b= %d\n", b);
    return b;
}

int test0_b(int a, int b)
{
    for(int i = 0; i < 10; i++){
        switch(a){
            case 1:
                printf("You chose the 1\n");
                break;
            case 2:
                printf("You chose the prime number 2\n");
            case 4:
                printf("You chose an even number\n");
                break;
            case 5:
               printf("both numbers are 5\n");
               goto L;
            case 3:
                printf("Another prime\n");
                break;
            case 7:
                printf("The 7 is a prime");
                goto L;
            default:
                printf("Number not between 1 and 5\n");
                if(a > 5){
                    a -= 5;
                }
                else{
                    a += 5;
                }

        }
        b += i;
        printf("b= %d\n", b);
    }
    L: printf("final b= %d\n", b);
    return b;
}

int test0_c(int a, int b)
{
    for(int i = 0; i < 10; i++){
        switch(a){
            case 1:
                printf("You chose the 1\n");
                break;
            case 2:
                printf("You chose the prime number 2\n");
            case 4:
                printf("You chose an even number\n");
                break;
            case 5:
               printf("both numbers are 5\n");
               goto L;
            case 3:
                printf("Another prime\n");
                break;
            case 7:
                if(b > 7){
                    b = b - 7;
                }
                printf("The 7 is a prime");
                goto L;
            default:
                printf("Number not between 1 and 5\n");
                if(a > 5){
                    a -= 5;
                }
                else{
                    a += 5;
                }

        }
        b += i;
        printf("b= %d\n", b);
    }
    L: printf("final b= %d\n", b);
    return b;
}

int test1()
{
    int week;
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
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

int test2()
{
    int month;

    /* Input month number from user */
    printf("Enter month number(1-12): ");
    scanf("%d", &month);

    switch(month)
    {
        /* Group all 31 days cases together */
        case 1:
        case 3:
        case 5:
        case 7:
        case 8:
        case 10:
        case 12: 
            printf("31 days");
            break;

        /* Group all 30 days cases together */
        case 4:
        case 6:
        case 9:
        case 11: 
            printf("30 days");
            break;

        /* Remaining case */
        case 2: 
            printf("28/29 days");
            break;

        default: 
            printf("Invalid input! Please enter month number between 1-12");
    }

    return 0;
}

int test3()
{
    int num1, num2;

    /* Input two numbers from user */
    printf("Enter two numbers to find maximum: ");
    scanf("%d%d", &num1, &num2);

    /* Expression (num1 > num2) will return either 0 or 1 */
    switch(num1 > num2)
    {   
        /* If condition (num1>num2) is false */
        case 0: 
            printf("%d is maximum", num2);
            break;

        /* If condition (num1>num2) is true */
        case 1: 
            printf("%d is maximum", num1);
            break;
    }

    return 0;
}

int test4()
{
    int num;

    printf("Enter any number: ");
    scanf("%d", &num);

    switch (num > 0)
    {
        // Num is positive
        case 1:
            printf("%d is positive.", num);
        break;

        // Num is either negative or zero
        case 0:
            switch (num < 0)
            {
                case 1: 
                    printf("%d is negative.", num);
                    break;
                case 0:
                    printf("%d is zero.", num);
                    break;
            }
        break;
    }

    return 0;
}

int test5()
{
    int week;
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
    {
        case 1: 
            printf("Monday");
            break;
        case 2: 
            printf("Tuesday");
            break;
        case 3: 
            printf("Wednesday");
        case 4: 
            printf("Thursday");
            break;
        case 5: 
            printf("Friday");
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

int test6()
{
    int week;
    //wo default
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
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
    }

    return 0;

}

int test7()
{
    int week;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
    {
        case 1: 
            printf("Monday");
            break;
        case 12: 
            printf("Tuesday");
            break;
        case 34: 
            printf("Wednesday");
            break;
        case 40: 
            printf("Thursday");
            break;
        case 500: 
            printf("Friday");
            break;
        case 6: 
            printf("Saturday");
            break;
        case 9: 
            printf("Sunday");
            break;
        default: 
            printf("Invalid input! Please enter week number between 1-7.");
    }

    return 0;

}

int test7_a()
{
    int week;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
    {
        case 0: 
            printf("Monday");
            break;
        case 12: 
            printf("Tuesday");
            break;
        case 34: 
            printf("Wednesday");
            break;
        case 400: 
            printf("Thursday");
            break;
        case 500: 
            printf("Friday");
            break;
        case 6: 
            printf("Saturday");
            break;
        case 9: 
            printf("Sunday");
            break;
        default: 
            printf("Invalid input! Please enter week number between 1-7.");
    }

    return 0;

}

int test7_b()
{
    int week;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
    {
        case 0: 
            printf("Monday");
            break;
        case 12: 
            printf("Tuesday");
            break;
        case 34: 
            printf("Wednesday");
            break;
        case 400: 
            printf("Thursday");
        case 500: 
            printf("Friday");
            break;
        case 6: 
            printf("Saturday");
            break;
        case 9: 
            printf("Sunday");
            break;
        default: 
            printf("Invalid input! Please enter week number between 1-7.");
    }

    return 0;

}

int test7_c()
{
    int week;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
    {
        case 0: 
            printf("Monday");
            break;
        case 12: 
            printf("Tuesday");
            break;
        case 34: 
            printf("Wednesday");
            break;
        case 40: 
            printf("Thursday");
            break;
        case 500: 
            printf("Friday");
            break;
        case 6: 
            printf("Saturday");
            break;
        case 9: 
            printf("Sunday");
            break;
        default: 
            printf("Invalid input! Please enter week number between 1-7.");
    }

    return 0;

}

int test8(){

    int digit;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter a digit (0-9): ");
    scanf("%d", &digit);
    
    switch(digit)
    {
        case 0: 
            printf("0");
            break;
        case 1: 
            printf("1");
            break;
        case 2: 
            printf("2");
            break;
        case 3: 
            printf("3");
            break;
        case 4: 
            printf("4");
            break;
        case 5: 
            printf("5");
            break;
        case 6: 
            printf("6");
            break;
        case 7: 
            printf("7");
            break;
        case 8: 
            printf("8");
            break;
        case 9: 
            printf("9");
            break;
        default: 
            printf("Not a digit");
    }

    return 0;
}

int test9(int week)
{
    switch(week+1)
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

int test10()
{
int a = rand();
int b = rand();
switch(a){
case 1: return 0;
case 5: a++;
case 10: a = a*2;
}
return a;
}

int test11(){
    int digit;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter a digit (0-9): ");
    scanf("%d", &digit);
    
    switch(digit)
    {
        case 0: 
            printf("0");
        case 1: 
            printf("1");
            break;
        case 2: 
            printf("2");
        case 3: 
            printf("3");
        case 4: 
            printf("4");
            break;
        case 5: 
            printf("5");
        case 6: 
            printf("6");
        case 7: 
            printf("7");
        case 8: 
            printf("8");
        case 9: 
            printf("9");
            break;
        default: 
            printf("Not a digit");
    }

    return 0;
}

int test12(){
    int digit;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter an even number between 4 and 14: ");
    scanf("%d", &digit);
    
    switch(digit)
    {
        case 4: 
            printf("2");
            break;
        case 6: 
            printf("3");
            break;
        case 8: 
            printf("4");
            break;
        case 10: 
            printf("5");
            break;
        case 12: 
            printf("6");
            break;
        case 14: 
            printf("7");
            break;
        default: 
            printf("Not in the range");
    }

    return 0;
}

int test13(){
    int digit;
    int half;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter an even number between 4 and 14: ");
    scanf("%d", &digit);
    printf("Enter 1 if you want to divide by two: ");
    scanf("%d", &half);
    
    switch(digit)
    {
        case 4: 
            if(half == 1){
                printf("2");
            } else{
                printf("4");
            }
            break;
        case 6: 
            if(half == 1){
                printf("3");
            }
            break;
        case 8: 
            printf("4");
            break;
        case 10: 
            printf("5");
            break;
        case 12: 
            printf("6");
            break;
        case 14: 
            printf("7");
            break;
        default: 
            printf("Not in the range");
    }

    return 0;
}

int test14(){
    int week;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
    {
        case 1: 
            case1: printf("Monday");
            goto case3;
            break;
        case 2: 
            printf("Tuesday");
            goto case3;
            break;
        case 3: 
            case3: printf("Wednesday");
            goto case7;
            break;
        case 4: 
            printf("Thursday");
        case 5: 
            printf("Friday");
            break;
        case 6: 
            case6: printf("Saturday");
            break;
        case 7: 
            case7: printf("Sunday");
            goto case6;
            break;
        default: 
            printf("Invalid input! Please enter week number between 1-7.");
    }

    return 0;
}

int test14_a(){
    int week;
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
    {
        case 2: 
            printf("Monday");
        case 1: 
            printf("Tuesday");
            goto case6;
            break;
        case 3: 
            printf("Wednesday");
        case 4: 
            printf("Thursday");
            goto case6;
            break;
        case 5: 
            printf("Friday");
            break;
        case 6: 
            case6: printf("Saturday");
        case 7: 
            printf("Sunday");
            break;
        default: 
            printf("Invalid input! Please enter week number between 1-7.");
    }
    return 0;
}

int test14_b(){
    int week;
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
    {
        case 1: 
            printf("Monday");
        case 2: 
            printf("Tuesday");
            goto case6;
            break;
        case 3: 
            printf("Wednesday");
        case 4: 
            printf("Thursday");
            goto case6;
            break;
        case 5: 
            printf("Friday");
            break;
        case 6: 
            case6: printf("Saturday");
        case 7: 
            printf("Sunday");
            break;
        default: 
            printf("Invalid input! Please enter week number between 1-7.");
    }
    return 0;
}

int test14_c(){
    int week;
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
    {
        case 1: 
            printf("Monday");
        case 2: 
            printf("Tuesday");
            if(week == 1){
                goto case3;
            }else{
                goto case5;
            }
            break;
        case 3: 
            case3: printf("Wednesday");
        case 4: 
            printf("Thursday");
            break;
        case 5: 
            case5: printf("Friday");
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

int test14_d(){
    int week;
    int numb;
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    printf("Enter 1 or 2): ");
    scanf("%d", &numb);
    
    switch(week)
    {
        case 1: 
            printf("Monday");
        case 2: 
            printf("Tuesday");
            if(numb == 1){
                goto case3;
            }else{
                goto case5;
            }
        case 3: 
            case3: printf("Wednesday");
        case 4: 
            printf("Thursday");
            break;
        case 5: 
            case5: printf("Friday");
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

int test15(){
    int week;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
    {
        case 1: 
            case1: printf("Monday");
            goto case3;
            break;
        case 2: 
            printf("Tuesday");
            break;
        case 3: 
            case3: printf("Wednesday");
            goto case7;
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
            case7: printf("Sunday");
            goto case1;
            break;
        default: 
            printf("Invalid input! Please enter week number between 1-7.");
    }

    return 0;
}

int test16(){
    int week;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
    {
        case 1: 
            case1: printf("Monday");
            goto case3;
            break;
        case 2: 
            printf("Tuesday");
        case 3: 
            case3: printf("Wednesday");
            goto case7;
            break;
        case 4: 
            printf("Thursday");
            break;
        case 5: 
            printf("Friday");
        case 6: 
            printf("Saturday");
            break;
        case 7: 
            case7: printf("Sunday");
            goto case1;
            break;
        default: 
            printf("Invalid input! Please enter week number between 1-7.");
    }

    return 0;
}

int test17(){
    int week;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    int count = 0;
    
    switch(week)
    {
        case 1: 
            case1: printf("Monday");
            goto case3;
            break;
        case 2: 
            printf("Tuesday");
            break;
        case 3: 
            case3: printf("Wednesday");
            goto case7;
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
            case7: printf("Sunday");
            if (count < 5){
                count++;
                goto case1;
            };
            break;
        default: 
            printf("Invalid input! Please enter week number between 1-7.");
    }

    return 0;
}

int test18()
{
    int week;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    switch(week)
    {
        case 1: 
            printf("Monday");
            // break;
            week +=500 ;
        case 12: 
            printf("Tuesday");
            break;
        case 500: 
            printf("Friday");
            // break;
        default: 
            printf("Invalid input! Please enter week number between 1-7.");
    }
    printf("the number is %d", week);
    return 0;

}

int test19()
{
    int week;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    
    if(week >= 40){
        week = rand();
        if(week == 50){
            printf("Friday");
        }else{
            goto default_case;
        }
    }else{

        switch(week)
        {
            case 1: 
                printf("Monday");
                break;
            case 12: 
                printf("Tuesday");
                break;
            case 34: 
                printf("Wednesday");
                break;
            case 40: 
                printf("Thursday");
                break;
            case 6: 
                printf("Saturday");
                break;
            case 9: 
                printf("Sunday");
                break;
            default: 
                default_case: printf("Invalid input! Please enter week number between 1-7.");
        }
    }
    return 0;
}

int test20(){
    int week;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);
    int time;
    printf("Enter a time (1-4): ");
    scanf("%d", &time);
    
    switch(week)
    {
        case 1: 
            switch(time){
                case 1:
                    printf("Monday morning");
                    break;
                case 2:
                    printf("Monday afternoon");
                    break;
                case 3:
                    printf("Monday evening");
                    break;
                case 4:
                    printf("Monday midnight");
                    break;
                default:
                    printf("Monday");
            }
            break;
        case 2: 
            printf("Tuesday");
            break;
        case 3: 
            printf("Wednesday");
            break;
        case 4: 
            switch(time){
                case 1:
                    printf("Thursday morning");
                    break;
                case 2:
                    printf("Thursday afternoon");
                    break;
                case 3:
                    printf("Thursday evening");
                    break;
                case 4:
                    printf("Thursday midnight");
                    break;
                default:
                    printf("Thursday");
            }
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

int test20_b(){
    int week;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter work-day number(1-7): ");
    scanf("%d", &week);
    int time;
    printf("Enter a time (1-2): ");
    scanf("%d", &time);
    
    switch(week)
    {
        case 1: 
            switch(time){
                case 1:
                    printf("Monday am");
                    break;
                case 2:
                    printf("Monday pm");
                    break;
                default:
                    printf("Monday");
            }
            break;
        case 2: 
            printf("Tuesday");
            break;
        case 3: 
            printf("Wednesday");
            break;
        case 4: 
            switch(time){
                case 1:
                    printf("Thursday am");
                    break;
                case 2:
                    printf("Thursday pm");
                    break;
                default:
                    printf("Thursday");
            }
            break;
        case 5: 
            printf("Friday");
            break;
        default: 
            printf("Invalid input! Please enter week number between 1-7.");
    }
    return 0;
}

int test21(){
    int digit;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter a digit (0-9): ");
    scanf("%d", &digit);
    
    switch(digit)
    {   
        default:
            printf("Not a digit");
        case 0: 
            printf("0");
        case 1: 
            printf("1");
            break;
        case 2: 
            printf("2");
        case 3: 
            printf("3");
        case 4: 
            printf("4");
            break;
        case 5: 
            printf("5");
        case 6: 
            printf("6");
        case 7: 
            printf("7");
        case 8: 
            printf("8");
        case 9: 
            printf("9");
    }

    return 0;
}

int test22()
{
    int month;

    /* Input month number from user */
    printf("Enter month number(1-12): ");
    scanf("%d", &month);

    switch(month)
    {
        /* Group all 31 days cases together */
        case 1:
        case 3:
        case 5:
            printf("first half of the year");
        case 7:
        case 8:
        case 10:
        case 12: 
            printf("31 days");
            break;

        /* Group all 30 days cases together */
        case 4:
        case 6:
        case 9:
        case 11: 
            printf("30 days");
            break;

        /* Remaining case */
        case 2: 
            printf("28/29 days");
            break;

        default: 
            printf("Invalid input! Please enter month number between 1-12");
    }

    return 0;
}

int test23(){
    int number;

    printf("Enter a number: ");
    scanf("%d", &number);
    
    printf("A number is dividable by %d:\n", number);
    switch(number)
    {   
        case 0: 
            printf("not possible");
            break;
//         case 1: 
//             printf("always");
//             break;
        case 2: 
            printf("last digit even");
            break;
        case 3: 
            printf("checksum dividable by 3");
            break;
//         case 4: 
//             printf("last two digist dividable by 4");
//             break;
        case 5: 
            printf("last digit is 0 0r 5");
            break;
//         case 8: 
//             printf("last three digist dividable by 8");
            break;
        case 10: 
            printf("last digit is 0");
            break;
//         case 16: 
//             printf("last four digist dividable by 16");
            break;
//         case 25: 
//             printf("last two digits dividable by 25");
//             break;
        case 100: 
            printf("the last two digits are 0");
            break;
//         case 125: 
//             printf("last three digits dividable by 125");
            break;
        default:
            printf("we have no rule");
    }

    return 0;
}

int test24(){
    char operator;
    int n1, n2;

    printf("Enter an operator (+, -, *, /): ");
    scanf("%c", &operator);
    printf("Enter two operands: ");
    scanf("%d %d",&n1, &n2);

    switch(operator)
    {
        case '+':
            printf("%d + %d = %d",n1, n2, n1+n2);
            break;

        case '-':
            printf("%d - %d = %d",n1, n2, n1-n2);
            break;

        case '*':
            printf("%d * %d = %d",n1, n2, n1*n2);
            break;

        case '/':
            printf("%d / %d = %d",n1, n2, n1/n2);
            break;

        // operator doesn't match any case constant +, -, *, /
        default:
            printf("Error! operator is not correct");
    }

    return 0;
}


int test25(){
    int number;

    printf("Enter : ");
    scanf("%d", &number);
    
    switch(number)
    {   
        case 0: 
            printf("Number is zero");
            break;
        case 1: 
            printf("Number is one");
            break;
        case 2: 
            printf("number is two");
            break;
        case 50: 
            printf("number is 50");
            break;
        default:
            printf("Error!");
    }

    return 0;
}

int test26(){

    int number;
    //Non sequential case constants
    
    /* Input week number from user */
    printf("Enter a digit (1-20): ");
    scanf("%d", &number);
    
    switch(number)
    {
        case 2: 
            printf("2 is a prime number.\n");
            break;
        case 3: 
            printf("3 is a prime number.\n");
            break;
        case 5: 
            printf("5 is a prime number.\n");
            break;
        case 7: 
            printf("7 is a prime number.\n");
            break;
        case 11: 
            printf("11 is a prime number.\n");
            break;
        case 13: 
            printf("13 is a prime number.\n");
            break;
        case 17: 
            printf("17 is a prime number.\n");
            break;
        case 19: 
            printf("19 is a prime number.\n");
            break;
        default: 
            printf("%d > 20 or not prime.\n", number);
    }

    return 0;
}

int test27(int a){
    int week;

    /* Input week number from user */
    printf("Enter week number(1-7): ");
    scanf("%d", &week);

    switch(week)
    {
        case 1:
            printf("%d", a+1);
            break;
        case 3:
            printf("%d", a+2);
            break;
        case 5:
            printf("%d", a+3);
            break;
    }
    scanf("%d", &a);
    switch(week){
        case 2:
            printf("%d", a+1);
            break;
        case 4:
            printf("%d", a+2);
            break;
        case 6:
            printf("%d", a+3);
            break;
    }

    return 0;
}

int test28(int week){

    switch(week)
    {
        case 1:
            printf("Monday");
            break;
        case 3:
            printf("Tuesday");
            break;
        case 5:
            printf("Wednesday");
            break;
    }
    week = week + 2;
    switch(week){
        case 2:
            printf("Thursday");
            break;
        case 4:
            printf("Friday");
            break;
        case 6:
            printf("Saturday");
            break;
    }

    return 0;
}

int test29(int week){

    switch(week)
    {
        case 1:
            printf("Monday");
            break;
        case 3:
            printf("Tuesday");
            break;
        case 5:
            printf("Wednesday");
            break;
    }
    week = week + 2;
    switch(week){
        case 2:
            printf("Thursday");
            break;
        case 4:
            printf("Friday");
            break;
        case 6:
            printf("Saturday");
            break;
	case 8:
	    printf("Sunday");
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
    test9(2);
    
	printf("Testing DREAM restruring algoritm\r\n");
}

