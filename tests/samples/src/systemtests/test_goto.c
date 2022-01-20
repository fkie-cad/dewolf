#include <stdio.h>
#include <stdlib.h>

int test1()
{
   /* local variable definition */
   int a = 10;

   /* do loop execution */
   LOOP:do {
   
      if( a == 15) {
         /* skip the iteration */
         a = a + 1;
         goto LOOP;
      }
		
      printf("value of a: %d\n", a);
      a++;

   }while( a < 20 );
 
   return 0;
}

int test1_b()
{
   /* local variable definition */
   int a = 10;

   /* do loop execution */
   LOOP:do {
   
      if( a <= 15) {
         /* skip the iteration */
         printf("value is: %d\n", a);
         a = a + 1;
         goto LOOP;
      }
		
      printf("value of a: %d\n", a);
      a++;

   }while( a < 20 );
   return 0;
}

int test1_c()
{
   /* local variable definition */
   int a = 10;

   /* do loop execution */
   LOOP:do {
   
      if( a == 15) {
         /* skip the iteration */
         printf("We go to the loop head.");
         a = a + 2;
         goto LOOP;
      }
		
      printf("value of a: %d\n", a);
      a++;

   }while( a < 20 );
 
   return 0;
}

int test2()
{
    int needle;
 
    /* get input from user*/
    printf("Please enter a number (0-10):");
    scanf("%d",&needle);
 
    int i;
           
    for(i = 0; i < 20;i++)
    {
        if(i == needle)
        {
            goto end;
        }
        else
        {
            printf("Current number %d\n",i);
        }
 
    }
    printf("Loop terminated normally.");
    goto label;
    printf("Loop terminated normally.2");
    
    label: printf("label and later end\n");
    end: printf("Jumped from the goto statement\n");
 
    return 0;
}

int test3()
{
    int i=1;

    start:
        goto print;

    print:
        printf("%d ", i);
        goto next;

    increment:
        i++;
        goto print;

    next:
        if(i < 10)
            goto increment;
        else
            goto exit;

    printf("I cannot execute.");

    exit:
        return 0;
}


int main()
{
	test1();
	test2();
	test3();

	printf("Testing DREAM restruring algoritm\r\n");
}

