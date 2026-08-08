/*
 * mmio_clean.c -- fixture C3 (DS-11): idiom bare-metal yang BENAR
 * (volatile, READ_REG, timeout, packed via per-byte, memcpy, ISR volatile).
 * Mode freestanding: harus bersih dari observasi C3.
 */
#include <stdint.h>
#include <string.h>

#define SR_ADDR ((volatile uint32_t *)0x40001000UL)

static inline uint32_t READ_REG(volatile uint32_t *r)
{
    return *r;
}

static uint32_t read_sr(void)
{
    return READ_REG(SR_ADDR);
}

static void wait_flag(void)
{
    unsigned timeout = 1000000;
    while (!(READ_REG(SR_ADDR) & 0x80) && timeout-- > 0)
        ;
}

struct packet {
    uint8_t  kind;
    uint32_t len;
    uint16_t crc;
};

static uint32_t read32(const uint8_t *buf, unsigned off)
{
    uint32_t v;
    memcpy(&v, buf + off, sizeof v);
    return v;
}

static volatile uint32_t g_counter;

static void timer_isr(void)
{
    g_counter++;
}

int main(void)
{
    struct packet p;
    uint8_t raw[8];

    read_sr();
    wait_flag();
    p.len = 4;
    read32(raw, 1);
    timer_isr();

    return (int)(g_counter + p.len);
}
