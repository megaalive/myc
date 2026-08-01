#define A A A A A
#define A(x) x x x
#define A A A
#undef A
#define A(x, ...) x __VA_ARGS__ x
int main(void) { return A(1, 2, 3, 4, 5); }
