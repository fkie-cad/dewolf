#include <stdio.h>
#include <stdlib.h>

void func(int * a){
    *a = 10;
}

/* -----------------------EP: propagating definitions that save current value of aliased variable -------------*/
int test0() {
    //almost minimal example to show why propagating assignments that save the current value of aliased variable
    // is a bad idea
    int x = rand() + 5;
    int *pointer = &x; // x is aliased
    int y = x; // y saves old value of x, do not replace y with x in return
    *pointer = rand() + 10; // changes aliased x
    printf("POINTER %d\n", *pointer);
    return y; // returns OLD value of x (saved in y)
}

int test1(){
    // this one shows that it is ok to propagate aliased to aliased assignment
    int x = rand() + 5;
    int *pointer = &x;
    int y = x;
    func(&x);
    printf("POINTER %d\n", x);
    return y;
}


int test2(){
    //show that non-propagating aliased can make the code uglier
    //but uncomment the lines (and undo non-propagation) to see that without it the code gets incorrect
    int x = 0;
    int y = 0;
    int * ptr_x = &x;
    int * ptr_y = &y;
    scanf("%d", ptr_x);
    scanf("%d", ptr_y);
    *ptr_x = 10;
    *ptr_y = 20;
    int z = x+y;
//    *ptr_x = 15;
//    *ptr_y = 30;
    return z;
}

int test3() {
    // check that we correctly return not the first saved aliased value, but any
    int x = rand() + 5;
    int *pointer = &x;
    *pointer = rand() + 6;
    int y = x;
    *pointer = rand() + 10;
    printf("POINTER %d\n", *pointer);
    return y;
}

int test14(){
    // example that shows that we are not allowed to propagate in calls also :(
    int x = rand()+1;
    int *ptr = &x;
    int y = x;
    *ptr = 10;
    printf("%d", y);
    return 0;
}



/*-----------------------------some experiments with dynamic arrays------------------------------*/
int test4(){
    // trying out if we decompile code with dynamic arrays correctly
    int *array = malloc(10 * sizeof(int));
    array[5] = 10;
    int y;
    scanf("%d", &y);
    array[8] = y;
    int x =  array[6]*7;
    free(array);
    return x;
}

int test5(){
    // trying out if we decompile code with dynamic arrays correctly v2
   int *array = malloc(10 * sizeof(int));
   array[5] = 10;
   int y;
   scanf("%d", &y);
   array[8] = y;
   int  x = array[6];
   if (array[8]<10){
       x*=7;
   }
   free(array);
   return x;
}

/*propagating to the uses when address of var is used also a bad idea*/

int test6() {
    //shows that we are not allow to propagate definitions x=1 and y=2 into prints
    //cause they are used in address operations and therefore could be changed
    // via dereferencing before they reach other uses (prints)
    int x = 1;
    int y = 2;
    int z = rand();
    int *pointer;
    if (z < 10) {
        pointer = &x;
    } else {
        pointer = &y;
    };
    *pointer = 3;
    printf("%d", x);
    printf("%d", y);
    return *pointer;
}


int test7(){
    // example for not propagating behind address use (similarly to 12) on 64 bits
    int *array = malloc(10 * sizeof(int));
    int y,x;
    x = 5;
    scanf("%d", &y);
    if(y<10){
        array[8] = 3;
        x = array[8];
        func(&x);//<----potentially causes problems
    }
    else{
        array[8] = 4;
        array[7] = 6;
    }
    int * z = &x;
    *z = 10;
    y = array[7];
    if(x!=y) array[9] = array[8];
    return array[8];
}

/*NOT EP: eliminating instructions still being used*/

int test8(){
    //almost minimal example to show that we eliminate x=3 although it is being used
    int x = rand() + 1;
    int *pointer = &x;
    int y = x;
    *pointer = rand() + 2;//<----change x(*ptr)
    *pointer = 4;//<----change x(*ptr)
    x = 3;//<----change x(*ptr)
    printf("%d", *pointer);//<----should print 3, but we delete the last assignment
    return y;
}

int test9(){
    // similar to 8; we are removing x = 3 although it is being used
    int x = rand() + 1;
    int *pointer = &x;
    int y = x;
    *pointer = rand() + 2;
    *pointer = 4;
    printf("%d", *pointer);
    x = 3;//<----should not be removed
    printf("%d", *pointer);
    return y;
}

int test10() {
    //shows that we are not allow to propagate definitions x=1 and y=2 into prints
    //cause they are used in address operations and therefore could be changed
    // via dereferencing before they reach other uses (prints)
    // not minimal example to show that we delete x=4 and y=5 although they influence the return value
    int x = 1;
    int y = 2;
    int z = rand();
    int *pointer;
    if (z < 10) {
        pointer = &x;
    } else {
        pointer = &y;
    };
    *pointer = 3;
    printf("%d", x);
    printf("%d", y);
    x = 4;
    y = 5;
    return *pointer;
}

/*CSE: ------------------Problem with this sample----------------------------------*/


int test11(){
    // Problem in common subexpression elimination, try to make it minimal
    int *array = malloc(10 * sizeof(int));
    int *array2 = malloc(10 * sizeof(int));
    int * ptr = array;
    int y,x;
    x = 5;
    scanf("%d", &y);
    if(y<10){
        ptr = array2;//<-----
        *(ptr+8) = 3;
        x = array[8];
        func(&x);
    }
    else{
        array[8] = 4;
        array[7] = 6;
    }
    y = ptr[7];
    if(x!=y) array[9] = array[8];
    return array[8];
}

int test12(){
// real - world example where we get dereference in plus operation fron Binja
    int x;
    x = 10;
    int y;
    int *ptr;
    scanf("%d", &y);
    x = y;
    ptr = &y;
    *ptr=7;
    return &x + y;
}


int test13(){
    int x = 0;
    int z;
    int * ptr;
    scanf("%d", &z);
    if (z>0){
        ptr = &x;
        *ptr = 10;
    }
    while(x<20){
        (*ptr)++;
    }
//    return x;
}

int test15(){
    // Problem in common subexpression elimination, try to make it minimal
    int *array = malloc(10 * sizeof(int));
    int y,x;
    x = 5;
    scanf("%d", &y);
    if(y<10){
         printf("%d", y);
         x = array[8];
    }
    else{
        array[8] = 4;
    }
    if(x!=y) array[9] = array[8];
    return array[8];
}
//--------------------------POINTERS----------------------------------
int test16(){
    // tests if branches aid the propagation
    // deref in same block as target
    int y, x;
    int * ptr;
    y = 0;
    ptr = &x;
    scanf("%d", ptr);

    if (x>0) y = x;
    *ptr = 20;
    printf("%d", y);
    return 0;
}

int test17(){
    // deref in conditional block between target and def
    int x = rand();
    int y, z;
    z = x;
    int * ptr_x = &x;
    scanf("%d", &y);
    if (y>10) *ptr_x = 15;
    printf("%d", x);
    return z;
}

int test18(){
    // deref in conditional block between target and def with changed mem indexes
    int x = rand();
    int y, z;
    int* ptr_x2;
    z = x;

    int * ptr_x = &x;
    scanf("%d", &y);
    if (y>10) {
        *ptr_x = 15;
        scanf("%d", &y);
        if (y<10) printf("%d", x);
    }
    printf("%d", x);
    return z;
}

int test19(){
 // example demontstrates when giving pointer instead of refs we should not also avoid propagating
    int x = rand() + 1;
    int y, z;
    int* ptr_x2;
    z = x;
    int * ptr_x = &x;
    printf("first block x %d", x);
    //scanf("%d", &x);
    scanf(ptr_x);
    if (y>10) {
    printf("first if x %d", x);
    //*ptr_x = 15;
    scanf("%d", &y);
    if (y<10) printf("second if x %d", x);
    }
    printf("ptr %d", x);
    return z;
}

int test20(){
// problem with ep
    int x;
    int * ptr = &x;
    x = rand() + 16;
    scanf("%d", &x);
    *ptr = 20;
    int y = x;
    return x;
}



int test21(){
//problem with missing definitions
// when fixed, problem with propagating copy of aliased to aliased
// behind its address being used
// problems when propagating address of dunno if it is fixed after ,e
    int x;
    int * ptr = &x;
    x = rand() + 16;
    scanf("%d", &x);
    *ptr = 20;
    return x;
}

int test22(){
//problem with missing definitions
// when fixed, problem with propagating copy of aliased to aliased
// behind its pointer being used
    int x;
    int * ptr = &x;
    x = rand() + 16;
    scanf("%d", ptr);
//    *ptr = 20;
    return x;
}


int test23() {
    //has to do with propagation of x(aliased) = smthng into others when no ptr dereferenced in between
    int x = rand() + 5;
    int *pointer = &x;
    *pointer = 15;
    int y = x;
    x = 10;
    printf("POINTER %d\n", y);
    return x;
}

int test24() {
    //has to do with propagation of x(aliased) = smthng into others when there is ptr deref
    int x = rand() + 5;
    int *pointer = &x;
    *pointer = 15;
    int y = x;
    x = 10;
    printf("POINTER %d\n", y);
    int z = x;
    printf("%d", z);
    *pointer = 20;
    return x;
}


int test25(int *arr, int len) {
    int cond = rand() + 5;
    int prev = 0;
    for (int i = 0; i < len; i++) {
        if (cond > 10) {
            prev = arr[i];
            arr[i] = arr[i]+10;
            printf("%d\n", prev);
        }
    }

}

int test26(){
// tests if we could get "dangerous" stuff duplicated
// yep

    int x, y, max;
    int *ptr = &x;
    scanf("%d",ptr);
    scanf("%d",&y);
    max = x;
    if (y>x){
       max = y;
       x = 10;
       scanf("%d",ptr);
    }
    return x;

}

test27(){
// try to make source/target duplicates
int y, x;
y = rand();
scanf("%d", x);
int *ptr = &x;
if (x<0){
printf("%d", x);
if(x<0){
printf("%d", x);
}
}
*ptr = 15;
printf("%d", x);
return x;
}
 test28(){
     int x = 1;
    int y = 2;
    int z = rand();
    int w = rand();
    int *pointer;
    while(w<10){
    if (z < 10) {
        pointer = &x;
    } else {
        pointer = &y;
    };
    *pointer = 3;
    w++;
    }
    printf("%d", x);
    printf("%d", y);

    return *pointer;
 }

 int test29() {
    //shows that we are not allow to propagate definitions x=1 and y=2 into prints
    //cause they are used in address operations and therefore could be changed
    // via dereferencing before they reach other uses (prints)
    // not minimal example to show that we delete x=4 and y=5 although they influence the return value
    int x = 1;
    int y = 2;
    int z = rand();
    int *pointer;
    if (z < 10) {
        pointer = &x;
    } else {
        pointer = &y;
    };
    *pointer = 3;
    printf("%d", x);
    printf("%d", y);
    x = 4;
    y = 5;
    int *pointer2 = pointer;
    *pointer2 = 3;
    return *pointer2;
}


 void f(int* arr){
  arr[0] = 12;
 }
int test30() {
    // trying out if we decompile code with dynamic arrays correctly
    int *array = malloc(10 * sizeof(int));
    array[5] = 10;
    int y;
    scanf("%d", &y);
    array[8] = y;
    int x =  array[6]*7;
    f(array);
    return x;
}

int test31() {
    // trying out if we decompile code with dynamic arrays correctly
    int *array = malloc(10 * sizeof(int));
    array[5] = 10;
    int y;
    scanf("%d", &y);
    array[8] = y;
    int x =  array[6]*7;
    array[6] = 15;
    return x;
}

int test32(){
    int y, x;
    int * ptr;
    y = rand() + 5;
    ptr = &y;
    x = y;
    scanf(ptr);
    return x;


}


int test33(){
    int x, y;
    int * ptr;
    y = rand() + 5;
    ptr = &y;
    x = y;
    scanf(ptr);
    return y;


}




int main(){
    test1();
}
