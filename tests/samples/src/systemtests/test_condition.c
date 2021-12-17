#include <stdio.h>
#include <stdlib.h>

int test1()
{
    int num1, num2, max;

    printf("Enter two numbers: ");
    scanf("%d%d", &num1, &num2);

    max = (num1 > num2) ? num1 : num2;

    printf("Maximum between %d and %d is %d", num1, num2, max);

    return 0;
}

int test2()
{
    int num1, num2, num3, max;

    printf("Enter three numbers: ");
    scanf("%d%d%d", &num1, &num2, &num3);


    max = (num1 > num2 && num1 > num3) ? num1 :
          (num2 > num3) ? num2 : num3;

    printf("\nMaximum between %d, %d and %d = %d", num1, num2, num3, max);

    return 0;
}

int test3()
{
    int num1, num2, num3, max;
    printf("Enter three numbers: ");
    scanf("%d%d%d", &num1, &num2, &num3);
    

    if(num1 > num2)
    {
        if(num1 > num3)
        {
            max = num1;
        }
        else
        {
            max = num3;
        }
    }
    else
    {
        if(num2 > num3)
        {
            max = num2;
        }
        else
        {
            max = num3;
        }
    }
    
    printf("Maximum among all three numbers = %d", max);

    return 0;
}

int test4()
{
    char ch;
    printf("Enter any character: \n");
    scanf("%c", &ch);

    if(ch=='a' || ch=='e' || ch=='i' || ch=='o' || ch=='u' || 
       ch=='A' || ch=='E' || ch=='I' || ch=='O' || ch=='U')
    {
        printf("'%c' is Vowel.", ch);
    }
    else if((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'))
    {
        printf("'%c' is Consonant.", ch);
    }
    else 
    {
        printf("'%c' is not an alphabet.", ch);
    }

    return 0;
}

int test5()
{
    char ch;
    printf("Enter any character: \n");
    scanf("%c", &ch);
    if(ch >= 'A' && ch <= 'Z')
    {
        printf("'%c' is uppercase alphabet.", ch);
    }
    else if(ch >= 'a' && ch <= 'z')
    {
        printf("'%c' is lowercase alphabet.", ch);
    }
    else
    {
        printf("'%c' is not an alphabet.", ch);
    }

    return 0;
}

int test6()
{
    int week;
    printf("Enter week number (1-7): ");
    scanf("%d", &week);


    if(week == 1)
    {
        printf("Monday");
    }
    else if(week == 2)
    {
        printf("Tuesday");
    }
    else if(week == 3)
    {
        printf("Wednesday");
    }
    else if(week == 4)
    {
        printf("Thursday");
    }
    else if(week == 5)
    {
        printf("Friday");
    }
    else if(week == 6)
    {
        printf("Saturday");
    }
    else if(week == 7)
    {
        printf("Sunday");
    }
    else
    {
        printf("Invalid Input! Please enter week number between 1-7.");
    }

    return 0;
}

int test7()
{
    int side1, side2, side3;
    printf("Enter three sides of triangle: \n");
    scanf("%d%d%d", &side1, &side2, &side3);
    
    if((side1 + side2) > side3)
    {
        if((side2 + side3) > side1)
        {
            if((side1 + side3) > side2) 
            {
                printf("Triangle is valid.");
            }
            else
            {
                printf("Triangle is not valid.");
            }
        }
        else
        {
            printf("Triangle is not valid.");
        }
    }
    else
    {
        printf("Triangle is not valid.");
    }

    return 0;
}

int test8()
{
    char ch;
    char a;
    printf("Enter any character: ");
    scanf("%c", &ch);
    a = ch;
    if (a>0x41){
        printf("%c", a);
    }
    return 0;

}

int test9()
{
    char ch;
    int a;
    printf("Enter any character: ");
    scanf("%c", &ch);
    a = ch*300;
    if (a>1024){
        printf("%d", a);
    }
    return 0;

}

int test10()
{   char chr;
    scanf("%c", &chr);
    unsigned char i = chr;
    printf("unsigned char: %c\n", i);
    return 0;
}

int test11()
{   long chr;
    scanf("%ld", &chr);
    unsigned long i = chr;
    printf("unsigned char: %lu\n", i);
    return 0;
}

struct st {
  int a;
  int b;
};

int test12() {
  struct st t = {0, 0};
  scanf("%d %d", &t.a, &t.b);
  if (t.a != t.b)
    printf("%d %d\n", t.a, t.b);
}

int test13()
{
    char ch;
    printf("Enter any character: ");
    scanf("%c", &ch);
    if(ch >= 0x41 && ch <= 0x5a)
    {
        printf("'%c' is uppercase alphabet.", ch);
    }
    else if(ch >= 0x61 && ch <= 0x71)
    {
        printf("'%c' is lowercase alphabet.", ch);
    }
    else
    {
        printf("'%c' is not an alphabet.", ch);
    }

    return 0;
}
int main()
{
	test4();
	test5();
	test13();


	printf("Testing DREAM restruring algoritm\r\n");
}


