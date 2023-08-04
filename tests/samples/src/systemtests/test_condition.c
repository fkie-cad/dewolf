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

int test6b()
{
    int week;
    printf("Enter week number (1-7): ");
    scanf("%d", &week);


    if(week != 1)
    {
    	if(week != 2)
    	{
    	    if(week != 3)
	    {
	        if(week != 4)
		{
		    if(week != 5)
		    {
		    	if(week != 6)
			{
		    	    if(week != 7)
			    {
		    		printf("Invalid Input! Please enter week number between 1-7.");
			    }
			    else
			    {
			    	printf("Sunday");
			    }
			}
			else
			{
			    printf("Saturday");
			}
		    }
		    else
		    {
			printf("Friday");
		    }
		}
		else
		{
		    printf("Thursday");
		}
	    }
	    else
	    {
	        printf("Wednesday");
	    }
    	}
    	else
    	{
    	    printf("Tuesday");
    	}
    }
    else
    {
        printf("Monday");
    }

    return 0;
}

int test6c()
{
    int week;
    printf("Enter week number (1-7): ");
    scanf("%d", &week);


    if(week == 1)
    {
        printf("Monday");
    }
    else if(week != 2)
    {
        if(week != 3)
        {
            if(week == 4)
            {
                printf("Thursday");
            }
            else if(week != 5)
            {
                if(week == 6)
                {
                    printf("Saturday");
                }
                else if(week != 7)
                {
                    printf("Invalid Input! Please enter week number between 1-7.");
                }
                else
                {
                    printf("Sunday");
                }
            }
            else
            {
                printf("Friday");
            }
        }
        else
        {
            printf("Wednesday");
        }
    }
    else
    {
    	printf("Tuesday");
    }

    return 0;
}

int test6d()
{
    int week;
    printf("Enter week number (1-7): ");
    scanf("%d", &week);


    if(week == 1)
    {
        printf("Monday");
    }
    else if(week != 2)
    {
        if(week != 3)
        {
            if(week == 4)
            {
                printf("Thursday");
            }
            else if(week != 5)
            {
                if(week == 6)
                {
                    printf("Saturday");
                }
                else if(week != 7)
                {
                    printf("Invalid Input! Please enter week number between 1-7.");
                }
                else
                {
                    printf("Sunday");
                }
            }
            else
            {
                printf("Friday");
            }
        }
        else
        {
            printf("Wednesday");
        }
    }

    return 0;
}

int test6e()
{
    int week;
    printf("Enter week number (1-7): ");
    scanf("%d", &week);


    if(week == 1)
    {
        printf("Monday");
    }
    else if(week != 2)
    {
        if(week == 3)
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
    }

    return 0;
}

int test6f()
{
    int week;
    printf("Enter week number (1-7): ");
    scanf("%d", &week);


    if(week != 2)
    {
        if(week == 3)
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

int test14()
{
    int num1, num2;
    printf("Enter two numbers: ");
    scanf("%d%d", &num1, &num2);
    

    if(num1 > 5){
        if(num2  > num1){
            printf("second number is larger than first");
            goto RETURN;
        }else{
            printf("first number is larger than second");
        }
    }else{
        printf("first number is <= 5");
    }
    num1 = 5;
    printf("set first number to 5");
    
    RETURN: return num1;
}

int test15()
{
    int num0, num1, num2;
    printf("Enter two numbers: ");
    scanf("%d%d%d", &num0, &num1, &num2);
    
    if(num0 > 10){
        if(num1 > 5){
            if(num2  > num1){
                printf("second number is larger than first");
            }else{
                printf("first number is larger than second");
                goto POS;
            }
        }else{
            printf("first number is <= 5");
        }
    }else{
        POS: num0 += num2;
    }
    printf("The numbers are: %d, %d, %d", num0, num1, num2);
    
    return 0;
}

int test16()
{
    int num0, num1, num2;
    printf("Enter two numbers: ");
    scanf("%d%d", &num0, &num1);
    
    if(num0 < 5){
        num0 += 5;
        if(num1 < 5){
            num1 += num0;
            }
    }else{
        num0 -= 5;
    }
    printf("The numbers are: %d, %d", num0, num1);
    return 0;
}

int test17(int a){
    int week;
    printf("Enter week number (1-7): ");
    scanf("%d", &week);
    

    if(week == 1){
        if(a == 7){
            printf("The Input is 7 and you choose week number %d", week);
            goto STEP;
        }
    }
    if(week == 2)
    {
        printf("Tuesday");
    }
    if(week == 3)
    {
        printf("Wednesday");
    }
    if(week == 4)
    {
        printf("Thursday");
    }
    if(week == 5)
    {
        printf("Friday");
    }
    if(week == 6)
    {
        printf("Saturday");
    }
    if(week == 7)
    {
        printf("Sunday");
    }

    if(week == 1){
        printf("Monday");
        STEP: printf("common case");
        return 0;
    }
    return 0;
}

int test18(int a){
    int week;
    printf("Enter week number (1-7): ");
    scanf("%d", &week);
    

    if(week == 1){
        printf("Possible switch case but not the one we want");
        if(a > 5){
            goto CASE1;
        }else{
            a += 5;
            goto CASE2;
        }
    }else{
        if(week == 2){
            CASE2: printf("Tuesday");
            if(a > 10){
                goto CASE3;
            }else{
                goto END;
            }
        }else{
            if(week == 3){
                CASE3: printf("Wednesday");
                if(week == 1){
                    CASE1: printf("Monday");
                    goto END;
                }
                goto CASE4;
            }else{
                if(week == 4){
                    CASE4: printf("Thursday");
                }
            }
        }
    }

    END: return 0;
}

int print_problem(){
  int b;
  scanf("%d", &b);
  printf("you entered: %d\n", b);
  b *= b;
  printf("squared: %d\n", b);
  return 0;
}

int main()
{
    test17(7);

	printf("Testing DREAM restruring algoritm\r\n");
}


