#include <stdio.h>

int main(void)
{
    FILE *f = fopen("secret.txt", "r");
    (void)f;
    return 0;
}
