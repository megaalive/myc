/* fixture Fase 6 (--thread-probe): LOCK-ORDER INVERSION.
 * f1 lock ma->mb, f2 lock mb->ma -- urutan terbalik = potensi deadlock.
 * Probe statis harus menandai LOCK-ORDER INVERSION (observasi
 * NON-blocking; verdict tetap OK). */
#include <pthread.h>

pthread_mutex_t ma, mb;

void f1(void)
{
    pthread_mutex_lock(&ma);
    pthread_mutex_lock(&mb);
    pthread_mutex_unlock(&mb);
    pthread_mutex_unlock(&ma);
}

void f2(void)
{
    pthread_mutex_lock(&mb);
    pthread_mutex_lock(&ma);
    pthread_mutex_unlock(&ma);
    pthread_mutex_unlock(&mb);
}

int main(void)
{
    return 0;
}
