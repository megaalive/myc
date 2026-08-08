/*
 * mmio_bad.c -- fixture C3 (DS-11): 5 pola bare-metal yang salah.
 * Mode freestanding: observasi NON-blocking harus memicu 5 diagnostic.
 */
#include <stdint.h>

#define SR_ADDR 0x40001000UL
#define DATA_ADDR 0x40001004UL

/* (1) MMIO deref alamat absolut tanpa volatile */
static uint32_t read_sr(void)
{
    return *(uint32_t *)SR_ADDR;
}

/* (2) polling loop tanpa volatile: while (!(reg & 0x80)); */
static void wait_flag(void)
{
    while (!(*(uint32_t *)SR_ADDR & 0x80))
        ;
}

/* (3) struct packed + field multi-byte */
struct __attribute__((packed)) packet {
    uint8_t  kind;
    uint32_t len;
    uint16_t crc;
};

/* (4) cast uint8_t* -> uint32_t* (alignment) */
static uint32_t read32(const uint8_t *buf, unsigned off)
{
    return *(uint32_t *)(const uint8_t *)(buf + off);
}

/* (5) variabel bersama ISR tanpa volatile */
static uint32_t g_counter;

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
