#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

int test1()
{
    int i, n;

    printf("Enter any number: ");
    scanf("%d", &n);

    printf("Natural numbers from 1 to %d : \n", n);

    for(i=1; i<=n; i++)
    {
        printf("%d\n", i);
    }

    return 0;
}

int test2()
{
    int num, sum=0, firstDigit, lastDigit;
    printf("Enter any number to find sum of first and last digit: ");
    scanf("%d", &num);
    lastDigit = num % 10;
    firstDigit = num;
    while(num >= 10)
    {
        num = num / 10;
    }
    firstDigit = num;
    sum = firstDigit + lastDigit; 
    printf("Sum of first and last digit = %d", sum);
    return 0;
}

int test3()
{
    int n, num = 0;

    printf("Enter any number to print in words: ");
    scanf("%d", &n);
    while(n != 0)
    {
        num = (num * 10) + (n % 10);
        n /= 10;
    }


    while(num != 0)
    {
        switch(num % 10)
        {
            case 0: 
                printf("Zero ");
                break;
            case 1: 
                printf("One ");
                break;
            case 2: 
                printf("Two ");
                break;
            case 3: 
                printf("Three ");
                break;
            case 4: 
                printf("Four ");
                break;
            case 5: 
                printf("Five ");
                break;
            case 6: 
                printf("Six ");
                break;
            case 7: 
                printf("Seven ");
                break;
            case 8: 
                printf("Eight ");
                break;
            case 9: 
                printf("Nine ");
                break;
        }
        
        num = num / 10;
    }

    return 0;
}

int test4()
{
    int i, num1, num2, max, lcm=1;
    printf("Enter any two numbers to find LCM: ");
    scanf("%d%d", &num1, &num2);
    max = (num1 > num2) ? num1 : num2;
    i = max;
    while(1)
    {
        if(i%num1==0 && i%num2==0)
        {
            lcm = i;
            break;
        }
        i += max;
    }

    printf("LCM of %d and %d = %d", num1, num2, lcm);

    return 0;
}

int test5()
{
    int i, j, end, isPrime; 
    printf("Find prime numbers between 1 to : ");
    scanf("%d", &end);
    printf("All prime numbers between 1 to %d are:\n", end);
    for(i=2; i<=end; i++)
    {
        isPrime = 1; 
        for(j=2; j<=i/2; j++)
        {
            if(i%j==0)
            {
                isPrime = 0;
                break;
            }
        }
        if(isPrime==1)
        {
            printf("%d, ", i);
        }
    }

    return 0;
}

int test6()
{
    int num, lastDigit, digits, sum, i, end;

    printf("Enter upper limit: ");
    scanf("%d", &end);

    printf("Armstrong number between 1 to %d are: \n", end);

    for(i=1; i<=end; i++)
    {
        sum = 0;
        num = i;
        digits = 0;
        while(num > 0)
        {
            lastDigit = num % 10;
            sum = sum + 1;
            num = num / 10;
        }
        if(i == sum)
        {
            printf("%d, ", i);
        }

    }

    return 0;
}

int test7()
{
    int OCTALVALUES[] = {0, 1, 10, 11, 100, 101, 110, 111};

    long long octal, tempOctal, binary, place;
    char hex[65] = "";
    int rem;

    place = 1;
    binary = 0;
    printf("Enter any octal number: ");
    scanf("%lld", &octal);
    tempOctal = octal;
    while(tempOctal > 0)
    {
        rem = tempOctal % 10;
        binary = (OCTALVALUES[rem] * place) + binary;
        tempOctal /= 10;

        place *= 1000;
    }
    

    while(binary > 0)
    {
        rem = binary % 10000;
        switch(rem)
        {
            case 0:
                strcat(hex, "0");
                break;
            case 1:
                strcat(hex, "1");
                break;
            case 10:
                strcat(hex, "2");
                break;
            case 11:
                strcat(hex, "3");
                break;
            case 100:
                strcat(hex, "4");
                break;
            case 101:
                strcat(hex, "5");
                break;
            case 110:
                strcat(hex, "6");
                break;
            case 111:
                strcat(hex, "7");
                break;
            case 1000:
                strcat(hex, "8");
                break;
            case 1001:
                strcat(hex, "9");
                break;
            case 1010:
                strcat(hex, "A");
                break;
            case 1011:
                strcat(hex, "B");
                break;
            case 1100:
                strcat(hex, "C");
                break;
            case 1101:
                strcat(hex, "D");
                break;
            case 1110:
                strcat(hex, "E");
                break;
            case 1111:
                strcat(hex, "F");
            break;
        }

        binary /= 10000;
    }

    printf("Octal number: %lld\n", octal);
    printf("Hexadecimal number: %s", hex);

    return 0;
}

int test8()
{
    int num;

    printf("Even numbers between 1 to 100: \n");

    for(num=1; num<=100; num++)
    {
        if(num % 2 == 1)
            continue;
        printf("%d ", num);
    }

    return 0;
}

int test9()
{
	while(1)
	{
		printf("a");
	}
	return 0;
}

int test10(int a, int b)
{
	while(( a <= 1 && b <= 100 ) || ( a> 1 && b <= 10))
	{
		printf("inside loop\r\n");
	}
	printf("loop terminated\r\n");
}

int test11(int a, int b)
{
	while(1){
        
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
	test10(1, 2);


	printf("Testing DREAM restruring algoritm\r\n");

}

