#include <stdio.h>
#include <stdlib.h>

/*
Test functions for parameter and return types of functions.

As long as the decompiler blindly trusts BinaryNinja for correctly guessing parameter and
return types, the results will be bogus whenever BinaryNinja guesses wrong.

Note: - compile with "gcc -O0" to prevent the test cases from being optimized away.
*/

/* Test recognition of different parameter types. */
int test1(char x, short y, int z, int *pointer) {
  int a = x;
  int b = y;
  return a + b + z + *pointer;
}

/* Helper functions for testing structs of different sizes as return values */

struct two_int {
  long a;
  long b;
};

struct three_int {
  long a;
  long b;
  long c;
};

struct four_int {
  long a;
  long b;
  long c;
  long d;
};

struct two_int default_two() {
  struct two_int x;
  x.a = 1 + (rand() % 2); // to prevent value propagation by BinaryNinja
  x.b = 2 + (rand() % 2); // to prevent value propagation by BinaryNinja
  return x;
}

struct three_int default_three() {
  struct three_int x;
  x.a = 3;
  x.b = 4;
  x.c = 5;
  return x;
}

struct four_int default_four() {
  struct four_int x;
  x.a = 6;
  x.b = 7;
  x.c = 8;
  x.d = 9;
  return x;
}

/* Test return types of different sizes.
This causes more than one return register or the stack to be used for return values.

On x86_64-linux there are two return registers. This causes the return value of default_two
to be returned through both registers, while default_three and default_four write
their return values onto the stack through a caller-provided pointer.
*/
void test2() {
  struct two_int x = default_two();
  printf("%d\n", x.a + x.b);              // prints 3, 4 or 5
  struct three_int y = default_three();
  printf("%d\n", y.a + y.b + y.c);        // prints 12
  struct four_int z = default_four();
  printf("%d\n", z.a + z.b + z.c + z.d);  // prints 30
}

int main() {
  printf("Test 1\n");
  int x = 1;
  printf("%d\n", test1(2, 3, 4, &x)); // prints 10
  printf("Test 2\n");
  test2();

  return 0;
}
