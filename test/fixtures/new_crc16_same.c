/* fixture A4 (DS-04): versi new -- refactor yang MEMPERTAHANKAN perilaku
 * (loop ditulis ulang, semantik sama) -> harus behavior-preserving. */

//@ requires crc >= 0 && crc <= 65535;
//@ requires byte >= 0 && byte <= 255;
//@ ensures crc >= 0 && crc <= 65535;
unsigned short crc16_update(unsigned short crc, unsigned char byte)
{
    unsigned short poly = 0xA001;
    crc = (unsigned short)(crc ^ byte);
    for (int k = 0; k < 8; k++) {
        if (crc & 1)
            crc = (unsigned short)((crc >> 1) ^ poly);
        else
            crc = (unsigned short)(crc >> 1);
    }
    return crc;
}

int main(void)
{
    return 0;
}
