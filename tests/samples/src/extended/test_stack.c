#include <stdio.h>
#include <stdlib.h>

/*
Test functions for indirect access to stack variables through pointer.

General Notes:
- Compile with "gcc -O0". On higher optimization levels many tests would be optimized away.
*/

/* Test simple tracking of references

- Last check: Error in dead code elimination, which falsely removes "x=2;". Should already been fixed.
*/
void test1() {
  int x = 1;
  int *pointer = &x;
  printf("%d\n", *pointer);           // prints 1
  int **pointer_pointer = &pointer;
  printf("%d\n", **pointer_pointer);  // prints 1
  x = 2;                              // This assignment is alive! Do not remove it during dead code elimination!
  printf("%d\n", **pointer_pointer);  // prints 2
  x = 3;                              // This assignment is technically dead, but can only be removed if one proves
                                      // that all pointers to x are already dead.
}

/* Test tracking of references where the target of a pointer is unknown at compile time.

- Last check: disassembles correctly.
*/
void test2() {
  int x = 1;
  int y = 2;
  int *pointer;
  if (rand() % 2 == 0) {
    pointer = &x;
  } else {
    pointer = &y;
  };
  printf("%d\n", *pointer); // prints 1 or 2
  *pointer = 3;
  printf("%d\n", x);        // prints 1 or 3
  printf("%d\n", y);        // prints 2 or 3
  x = 4;                    // Assignment is alive through the pointer
  y = 5;                    // Assignment is alive through the pointer
  printf("%d\n", *pointer); // prints 4 or 5
}

/* Test operations, that only read or write a part of a dereferenced variable

- Last check: Error, analysis seems to be unable to recognize overlapping variables at all
and thus dead-code-eliminates the assignments to two_chars.two
*/
void test3() {
  /* structs in C have a well-defined memory layout, thus interpreting a struct
  consisting of 2 chars as a 2-byte-short is well-defined. */
  struct {
    char one;
    char two;
  } two_chars;
  two_chars.one = 4;
  two_chars.two = 1;
  short *pointer = (void *) &two_chars;
  printf("%d\n", *pointer); // prints 260 (on little-endian cpu architectures)
  two_chars.two = 2;        // Assignment is alive through the pointer
  printf("%d\n", *pointer); // prints 516 (on little-endian cpu architectures)

  short x = 256;
  char *char_pointer = (void *) &x + 1;
  printf("%d\n", *char_pointer);  // prints 1 (on little-endian cpu architectures)
  x = 516;                        // Assignment is alive through char_pointer
  printf("%d\n", *char_pointer);  // prints 2 (on little-endian cpu architectures)
}

/* Test array operations

- Last check: Error, the user cannot reconstruct the offset of the variables on the stack
and thus can neither see that array[5] actually lies in the array nor at which offset.
The renaming in the out-of-ssa-translation destroys the last bit of stack-position-information
from BinaryNinja.
*/
void test4() {
  int array[10];
  for (int i = 0; i<10; i++) {
    array[i] = i;
  };
  int *pointer = &array[5];
  printf("%d\n", *pointer); // prints 5
  *pointer = 11;
  printf("%d\n", array[5]); // prints 11
  array[4] = 12;            // Assignment is alive since the whole array is still alive
  for (int i = 0; i<10; i++) {
    printf("%d; ", array[i]);
  };                        // prints "0; 1; 2; 3; 12; 11; 6; 7; 8; 9;"
  printf("\n");
}

int read_through_pointer(int *pointer) {
  return *pointer;
}

void write_through_pointer(int *pointer, int value) {
  *pointer = value;
}

/* Test read/writes through function calls

- Last check: disassembles correctly.
*/
void test5() {
  int x = 1;
  int *pointer = &x;
  printf("%d\n", read_through_pointer(pointer)); // prints 1
  write_through_pointer(pointer, 2);
  printf("%d\n", x);                             // prints 2
  x = 3;                                         // assignment is alive through pointer
  printf("%d\n", read_through_pointer(pointer)); // prints 3
}

/* Test read/writes with different sizes through pointer

- Last check: Error. The size information of the reads and writes seems to be
already lost at the starting point, where all variables seem to be pointer-sized
regardless of their actual size.
*/
void test6() {
  short x = 258;
  short *y = &x;
  printf("%d\n", *y); // prints 258
  printf("%d\n", *((char*) y)); // prints 2
  *((char*) y) = 3;
  printf("%d\n", *y); // prints 259
  printf("%d\n", *((char*) y)); // prints 3
}

int main() {
  printf("Test 1\n");
  test1();
  printf("Test 2\n");
  test2();
  printf("Test 3\n");
  test3();
  printf("Test 4\n");
  test4();
  printf("Test 5\n");
  test5();
  printf("Test 6\n");
  test6();
  return 0;
}
