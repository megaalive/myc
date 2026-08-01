#include <stdlib.h>

#define RUN system

int main(void)
{
    RUN("echo pwned");
    return 0;
}
