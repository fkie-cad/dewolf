#include <stdio.h>
#include <stdlib.h>

/*
Test functions for type conversions.

Note: - compile with "gcc -O0" to prevent the test cases from being optimized away.
*/

/* Test conversions between char and short */
void test1() {
  char x = 125;
  printf("%d\n", x);  // prints 125
  char y = x + 126;   // (signed) integer overflow
  short z = ((short) x) + 126;  // no integer overflow
  printf("%d\n", y);  // prints -5
  printf("%d\n", z);  // prints 251
  x = z;  // conversion from short to char
  printf("%d\n", x);  // prints -5
}

/* Test conversions between signed and unsigned */
void test2() {
  short divisor = -5 + (rand() % 2);
  short x = -7;
  unsigned short y = x;
  printf("%d\n", x);  // prints -7
  printf("%d\n", y);  // prints 65529
  x = x / divisor;
  y = y / (unsigned short) divisor;
  short z = y;
  printf("%d\n", x);  // prints 1
  printf("%d\n", z);  // prints 0
}

/* Test conversion from pointer to integer */
void test3() {
  int x = 1;
  int *y = &x;
  printf("%d\n", y);  // prints some address
  printf("%d\n", *y); // prints 1
}

int main () {
  printf("Test 1\n");
  test1();
  printf("Test 2\n");
  test2();
  printf("Test 3\n");
  test3();

  return 0;
}
