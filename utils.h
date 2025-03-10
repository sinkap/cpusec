#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <err.h>

#define str(s) #s
#define xstr(s) str(s)

#define NOP asm volatile("nop")
#define NOPS_str(n) ".rept " xstr(n) "\n\t"\
    "nop\n\t"\
    ".endr\n\t"


#define str(s) #s
#define xstr(s) str(s)

#define NOP asm volatile("nop")
#define NOPS_str(n)                                                            \
  ".rept " xstr(n) "\n\t"                                                      \
                   "nop\n\t"                                                   \
                   ".endr\n\t"

#define MMAP_FLAGS                                                             \
  (MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_FIXED_NOREPLACE)
#define PROT_RW (PROT_READ | PROT_WRITE)
#define PROT_RWX (PROT_RW | PROT_EXEC)

#define PG_ROUND(n) (((((n) - 1UL) >> 12) + 1) << 12)

/*
 * Calculates the Branch Target Buffer (BTB) index for a given address on AMD Zen 2 processors.
 * This function implements the reverse-engineered hash function used by Zen 2 to map
 * instruction addresses to BTB entries.  A collision in this hash function (different
 * addresses mapping to the same BTB index) can lead to Branch Target Injection (BTI)
 * vulnerabilities (Spectre variant 2).
 *
 * The image you provided shows the following bitwise operations:
 *
 * Zen 2 BTB Index Calculation (from image):
 *   f1  = b36 ^ b24
 *   f2  = b37 ^ b25
 *   f3  = b38 ^ b26
 *   f4  = b39 ^ b27 ^ (b15 & b10)
 *   f5  = b40 ^ b28 ^ (b16 & b11)
 *   f6  = b41 ^ b29 ^ b17
 *   f7  = b42 ^ b30 ^ b18
 *   f8  = b43 ^ b31 ^ b19
 *   f9  = b44 ^ b32 ^ b20
 *   f10 = b45 ^ b33 ^ b21
 *   f11 = b46 ^ b34 ^ b22
 *   f12 = b47 ^ b35 ^ b23
 *
 * Where:
 *   - '^' denotes the bitwise XOR operation.
 *   - '&' denotes the bitwise AND operation.
 *   - bN represents the Nth bit of the input address (starting from bit 0).
 *   - fN represents the Nth folding function, which contributes to a bit of the index.
 *
 *  The overall index is conceptually formed by concatenating the results of f1 through f12.
 *  However, since the code uses bitwise XOR to accumulate the results into a single `index`
 *  variable, the order of operations doesn't matter. The final `index` will have bits set
 *  corresponding to where an odd number of the 'f' functions would have produced a '1'.
 */
 static inline uint16_t zen2_btb_index(uint64_t addr) {
  uint16_t index = 0;

  /* f1 = b36 ^ b24 */
  index ^= ((addr >> 36) & 1) ^ ((addr >> 24) & 1);

  /* f2 = b37 ^ b25 */
  index ^= ((addr >> 37) & 1) ^ ((addr >> 25) & 1);

  /* f3 = b38 ^ b26 */
  index ^= ((addr >> 38) & 1) ^ ((addr >> 26) & 1);

  /* f4 = b39 ^ b27 ^ (b15 & b10) */
  index ^= ((addr >> 39) & 1) ^ ((addr >> 27) & 1) ^
           (((addr >> 15) & 1) & ((addr >> 10) & 1));

  /* f5 = b40 ^ b28 ^ (b16 & b11) */
  index ^= ((addr >> 40) & 1) ^ ((addr >> 28) & 1) ^
           (((addr >> 16) & 1) & ((addr >> 11) & 1));

  /* f6 = b41 ^ b29 ^ b17 */
  index ^= ((addr >> 41) & 1) ^ ((addr >> 29) & 1) ^ ((addr >> 17) & 1);

  /* f7 = b42 ^ b30 ^ b18 */
  index ^= ((addr >> 42) & 1) ^ ((addr >> 30) & 1) ^ ((addr >> 18) & 1);

  /* f8 = b43 ^ b31 ^ b19 */
  index ^= ((addr >> 43) & 1) ^ ((addr >> 31) & 1) ^ ((addr >> 19) & 1);

  /* f9 = b44 ^ b32 ^ b20 */
  index ^= ((addr >> 44) & 1) ^ ((addr >> 32) & 1) ^ ((addr >> 20) & 1);

  /* f10 = b45 ^ b33 ^ b21 */
  index ^= ((addr >> 45) & 1) ^ ((addr >> 33) & 1) ^ ((addr >> 21) & 1);

  /* f11 = b46 ^ b34 ^ b22 */
  index ^= ((addr >> 46) & 1) ^ ((addr >> 34) & 1) ^ ((addr >> 22) & 1);

  /* f12 = b47 ^ b35 ^ b23 */
  index ^= ((addr >> 47) & 1) ^ ((addr >> 35) & 1) ^ ((addr >> 23) & 1);

  return index;
}

static inline int check_zen2_btb_collision(uint64_t addr1, uint64_t addr2) {
  return zen2_btb_index(addr1) == zen2_btb_index(addr2);
}

#define map_or_die(...)                                                        \
  do {                                                                         \
    if (mmap(__VA_ARGS__) == MAP_FAILED)                                       \
      err(1, "mmap");                                                          \
  } while (0)

static inline void set_cpu_affinity(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

static inline __attribute__((always_inline)) void flush_range(long start, long stride, int n) {
  asm("mfence");
  for (uint64_t k = 0; k < n; ++k) {
      volatile void *p = (uint8_t *)start + k * stride;
      __asm__ volatile("clflushopt (%0)\n"::"r"(p));
      __asm__ volatile("clflushopt (%0)\n"::"r"(p));
  }
  asm("lfence");
}