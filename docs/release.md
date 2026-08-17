# Release provenance (P11)

Bagaimana rilis myc dibuat, apa yang dijanjikan, dan apa yang **tidak**.

## Syarat sebelum tag

Jangan membuat tag sebelum `master` di-push dan CI hijau.

1. `git push origin master`
2. Tunggu `.github/workflows/ci.yml` **success** di `master`
3. `bash release-guard.sh`
4. `git tag vX.Y.Z` lalu `git push --tags`

Workflow [`.github/workflows/release.yml`](../.github/workflows/release.yml)
berjalan pada tag `v*` dan mengunggah biner Linux + Windows.

## Artefak

Setiap rilis GitHub berisi:

| File | Host |
|---|---|
| `myc`, `mcp`, `argv_probe` | Linux x86-64 |
| `myc.exe`, `mcp.exe`, `argv_probe.exe` | Windows x86-64 |
| `SHA256SUMS` | checksum SHA-256 dari keenam biner |

Catatan rilis memuat **source commit** (git SHA tag). Biner rilis di-stempel
`-DMYC_GIT_SHA=<sha>` sehingga `myc version` mencetak `git: <sha>`.
Build lokal tanpa env itu mencetak `git: unstamped`.

## Rebuild (bukan bit-identical)

Untuk membangun ulang dari sumber yang sama:

```text
git checkout <tag>
MYC_GIT_SHA=<sha-tag> bash build.sh     # Linux
set MYC_GIT_SHA=<sha-tag> & build.bat   # Windows
```

Toolchain: gcc yang dipakai CI (lihat `ci.yml` / image runner). **Bit-identical
binaries tidak diklaim** — patch gcc, timestamp objek, dan path build bisa
berbeda. Provenance yang dijanjikan:

- git SHA tag = sumber
- `SHA256SUMS` = isi artefak yang diunggah
- `myc version` → `git:` pada biner rilis = SHA yang sama

Bila checksum unduhan tidak cocok `SHA256SUMS`, jangan dipakai.

## Rollback

Pakai artefak tag sebelumnya. Lihat juga [`docs/incident.md`](incident.md).
