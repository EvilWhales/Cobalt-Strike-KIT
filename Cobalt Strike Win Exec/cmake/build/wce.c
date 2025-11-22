#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "secret.h"

unsigned long cpu_clock();
int sort_cmp(const void *a, const void *b);
int check_password(char* password);
char* crack_password(int rounds);

int main(int argc, char **argv) {
	srand(time(NULL));

	int rounds = 1024;
	if (argc > 1) {
		rounds = atoi(argv[1]);
	} else {
		printf("Defaulting to %d rounds.\n", rounds);
		printf("To change the number of rounds, use: %s [rounds]\n", argv[0]);
	}

	char *password = crack_password(rounds);

	if (password == NULL) {
		printf("Unable to crack.\n");
	} else {
		printf("Password: \"%s\"\n", password);
		free(password);
	}

	return 0;
}

int sort_cmp(const void *a, const void *b) {
	return (*(unsigned long*)a - *(unsigned long*)b);
}

char* crack_password(int rounds) {
	const int length = 64;
	const char lower_bound = 32;
	const char upper_bound = 127;
	const int range = upper_bound - lower_bound;

	char *password = malloc(length);

	if (password == NULL) {
		exit(1);
	}

	memset(password, 0, length);

	char pass_rnd_align[length + 64];

	int *attempt_cycles[range];

	for (int i = 0; i < range; i++) {
		attempt_cycles[i] = malloc(rounds * sizeof(int));

		if (attempt_cycles[i] == NULL) {
			for (int j = 0; j < i; j++) {
				free(attempt_cycles[j]);
			}

			free(password);

			exit(1);
		}
	}

	int median_cycles[range];

	char charset[range];

	for (char c = lower_bound; c < upper_bound; c++) {
		charset[c - lower_bound] = c;
	}

	printf("Attempting to crack password with %d rounds...\n", rounds);

	for (int i = 0; i < length - 1; i++) {

		for (int j = 0; j < rounds; j++) {

			for (int k = 0; k < range; k++) {
				int swap = rand() % range;

				char temp = charset[k];
				charset[k] = charset[swap];
				charset[swap] = temp;
			}

			int offset = rand() & 63;
			char *pass_rnd_align_ptr = pass_rnd_align + offset;
			strcpy(pass_rnd_align_ptr, password);
			pass_rnd_align_ptr[i + 1] = '\0';

			for (int k = 0; k < range; k++) {
				char c = charset[k];
				int char_index = c - lower_bound;

				pass_rnd_align_ptr[i] = c;

				unsigned long start = cpu_clock();

				if (check_password(pass_rnd_align_ptr)) {
					for (int i = 0; i < range; i++) {
						free(attempt_cycles[i]);
					}

					password[i] = c;
					return password;
				}

				unsigned long end = cpu_clock();
				int duration = end - start;

				attempt_cycles[char_index][j] = duration;
			}
		}

		for (int j = 0; j < range; j++) {
			qsort(attempt_cycles[j], rounds, sizeof(int), sort_cmp);

			median_cycles[j] = attempt_cycles[j][rounds >> 1];
		}

		int max_cycles = 0;
		char candidate;
		for (char k = lower_bound; k < upper_bound; k++) {
			int char_index = k - lower_bound;
			password[i] = k;

			if (median_cycles[char_index] > max_cycles) {
				candidate = k;
				max_cycles = median_cycles[char_index];
			}
		}

		password[i] = candidate;

		printf("Still no hax. Best guess yet: \"%s\"\n", password);
	}

	free(password);
	for (int i = 0; i < range; i++) {
		free(attempt_cycles[i]);
	}

	return NULL;
}

