#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

uint64_t adc(uint64_t a, uint64_t b)
{
    a += b;
    if (a < b) /* should simplify to nothing (setting carry is implicit in the add) */
        a++; /* should simplify to adc r0, 0 */
    return a;
}

// gcc wastes a bunch of mov instructions, but clang doesn't
// __uint128_t add128(__uint128_t a, __uint128_t b) {
//   return a + b;
// }

int main() {
    return adc(1, getpid());
}
