// Fixture P7 (D1.5): kontrak requires valid, dipenuhi.
//@ requires n > 0;
int twice(int n) {
    return n * 2;
}

//@ requires len > 0;
//@ ensures res > 0;
int first(char *buf, int len) {
    return buf[0] + len;
}

int main(void) {
    return twice(21) == 42 ? 0 : 1;
}
