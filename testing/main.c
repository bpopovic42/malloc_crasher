#include <stdlib.h>
#include <stdio.h>

int protected_malloc_call(void)
{
	void *tmp;

	if ((tmp = malloc(1)))
	{
		free(tmp);
		return (0);
	}
	else
		return (1);
}

void unprotected_malloc_call(void)
{
	char *tmp;

	tmp = malloc(1);
	tmp[0] = 'a';
	free(tmp);
}

int main(void)
{
	unprotected_malloc_call();
	if (protected_malloc_call() != 0)
	{
		puts("Allocation failed ! ...");
		return (1);
	}
	unprotected_malloc_call();
	puts("Terminating ...");
	return (0);
}
