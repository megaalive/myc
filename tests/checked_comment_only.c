/* checked_comment_only.c -- Fixture MYC-AUDIT-026 (roadmap 7.3): NO
 * OVER-CLAIM. Source yang HANYA MENYEBUT "MYC_BUF" di komentar TIDAK boleh
 * memicu gate checked: `myc check --checked` harus di-skip (diagnostic
 * "checked build di-skip: tidak ada pola MYC_BUF di source") dan TIDAK boleh
 * memunculkan baris coverage / field checked_buffers (L4 tidak diklaim).
 *
 * Komentar di bawah ini berisi "MYC_BUF(int)" — bukan deklarasi sungguhan.
 */
/* MYC_BUF(int) b; -- hanya komentar, bukan deklarasi fat-buffer. */

int main(void)
{
    return 0;
}
