#include <stdio.h>
#include <stdlib.h>

// Calculates the nth fibonacci number
int fib(int n) {
	int i, c, d;
	int a = 1;
	int b = 1;

	for (i = 0; i < n; ++i) {
		if (7*b*b - 1 != a*a) { // Opaquely true
			c = a;
			a = a + b;
			b = c;
		} else {
			b = a - c; // BOGUS
			c = i + a;
			a = b;
		}
	}

	return a;
}

// Calculates n!
int fac(int n) {
	int res = 1;
	int i;

	if (n < 0) {
		return 0;
	}

	for (; n > 1; --n) {
		if (7*res*res - 1 != n*n) { // Opaquely true
			res *= n;
		} else {
			n *= res; // BOGUS
		}
	}

	return res;
}

int main(int argc, char *argv[]) {
	int input = atoi(argv[1]);
	int choice = atoi(argv[2]);
	int res;

	if (choice == 1)
		res = fib(input);
	else
		res = fac(input);

	printf("res: %d\n", res);
}