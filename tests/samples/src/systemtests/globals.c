#include <stdint.h>
#include <stdio.h>


int global_table(unsigned x) {
	static char table[64] =
	{32,20,19, 99, 99,18, 99, 7,  10,17, 99, 99,14, 99, 6, 99,
		99, 9, 99,16, 99, 99, 1,26,   99,13, 99, 99,24, 5, 99, 99,
		99,21, 99, 8,11, 99,15, 99,   99, 99, 99, 2,27, 0,25, 99,
		22, 99,12, 99, 99, 3,28, 99,  23, 99, 4,29, 99, 99,30,31};

	x = x | (x >> 1); 
	x = x | (x >> 2);
	x = x | (x >> 4);
	x = x | (x >> 8);
	x = x & ~(x >> 16);
	x = (x << 9) - x;
	x = (x << 11) - x;
	x = (x << 14) - x;
	return table[x >> 26];
}

volatile int32_t g_3 = -2L;
volatile int32_t * volatile g_2 = &g_3;

int64_t global_indirect_ptrs(volatile int32_t * volatile *l4)
{
	*l4 = g_2;
	return *(*l4);
}



const int32_t g_9 = 1L;
uint16_t g_22 = 0xD3E9L;
int8_t g_26 = 0x9DL;
int16_t g_29[2][1] = {{1L}, {1L}};
uint8_t g_30 = 0xECL;
int32_t g_32 = 0x5E13CD4FL;
uint8_t g_35 = 255UL;
int32_t * volatile g_36 = (void *) 0;
int32_t g_38 = 0x07CB0BE9L;

int32_t global_ias(uint8_t l_2)
{
	int32_t l_20[1][3][7] = {{{0x6DBC1C23L, 0x79AE4F78L, 0x79AE4F78L, 0x6DBC1C23L, 0x79AE4F78L, 0x79AE4F78L, 0x6DBC1C23L}, {1L, 0x7CBAE8B0L, 1L, 1L, 0x7CBAE8B0L, 1L, 1L}, {0x6DBC1C23L, 0x6DBC1C23L, 0x213072C0L, 0x6DBC1C23L, 0x6DBC1C23L, 0x213072C0L, 0x6DBC1C23L}}};
	uint16_t *l_21 = &g_22;
	int8_t *l_25 = &g_26;
	uint8_t l_27 = 0xF3L;
	int16_t *l_28 = &g_29[0][0];
	int32_t *l_31 = &g_32;
	uint8_t *l_33 = (void *) 0;
	uint8_t *l_34[5];
	int32_t *l_37[4] = {&g_38, &g_38, &g_38, &g_38};
	int i;
	int j;
	int k;
	for (i = 0; i < 5; i++)
		l_34[i] = &l_27;

	g_38 ^= l_2 > (((uint8_t) (g_35 = ((((uint16_t) (((int64_t) ((*l_31 = ((g_9 == l_2) < (l_20[0][0][3] = (0xC61CL < (((((uint8_t) ((((uint16_t) g_9) >> ((uint16_t) (g_30 = (*l_28 &= ((((uint32_t) g_9) * ((uint32_t) (((int16_t) ((((l_2, ((((int64_t) (((*l_21)++) == (((*l_25 = g_9) || l_27, 0x0237L)))) * ((int64_t) l_2)) == 0xBDL) != 0x191A83ACDD711A53LL)) ^ 0x04ED09EB818F8F6ALL) || l_20[0][1][1])) >> ((int16_t) 2)))) && 0xE71CC545L) >= g_9)))) >= g_9)) << ((uint8_t) g_9)) <= g_9) || l_20[0][1][1])) | l_20[0][1][1])) != l_2, g_32))) << ((int64_t) g_9))) - ((uint16_t) 0x4F86L)) <= g_9) & g_9)) / ((uint8_t) g_9));
	return *l_31;
}


int _add(int* a, int* b){
    *a = *b;
    return *a + *a;
}


int a;
int b;

int global_addr_add(){
    return _add(&a, &b);
}


int* c;
int* d;

int global_ptr_add(){
    return _add(c, d);
}


int e = 0x17;
int f = 0x42;
int* g = &e;
int* h;

int global_addr_ptr_add(){
    h = &f;
    return _add(g, h);
}


struct cool_data_structure{
    int x;
    char y;
    int z;
};


int _add_struct(struct cool_data_structure* s){
    return s->x + (int) s->y + s->z;
}


struct cool_data_structure i;

int global_add_struct(){
    return _add_struct(&i);
}


char* j = "Hello Decompiler!";
void* k = (void*) "Hello Void*!";

int global_strings(){
    puts("Hello World!");
    puts(j);
    puts(k);
    return 0;
}


int (*l)(int*, int*);

int global_fkt_ptr(){
    l = &_add;
    return l(&a,&b);
}


int p = -0x42;
int* o = &p;
int** n = &o;
int*** m = &n;

int global_indirect_ptrs2(){
    return _add(**m, &p);
}

int* q	= (int*) &q;


int global_recursive_ptr(){
    return _add(q, q);
}

int global_string_compare(char* ptr){
	if(ptr == "Hello Decompiler")
		return 1;
	return 0;
}

int main(int argc, char *argv[]) {
	global_table(argc);
	global_addr_add();
	global_ptr_add();
	global_addr_ptr_add();
	global_add_struct();
	global_strings();
	global_fkt_ptr();
	global_indirect_ptrs2();
	global_recursive_ptr();
	return 0;
}
