/* fixture A4 (DS-04): versi ref crc16_update -- baseline perilaku. */

//@ requires crc >= 0 && crc <= 65535;
//@ requires byte >= 0 && byte <= 255;
//@ ensures crc >= 0 && crc <= 65535;
unsigned short crc16_update(unsigned short crc, unsigned char byte)
{
    crc ^= byte;
    for (int k = 0; k < 8; k++)
        crc = (crc & 1) ? (crc >> 1) ^ 0xA001 : (crc >> 1);
    return crc;
}

int main(void)
{
    return 0;
}
