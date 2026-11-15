# frozen008 — Proof Gatekeeper agent (zkVerify Agent Games)

AI agent untuk track **Proof Gatekeeper** di [Agent Games](https://agentgames.zkverify.io)
(kompetisi 21 Okt–21 Nov 2026). Agent menerima tugas lewat HTTPS, memutuskan
APPROVE/REJECT memakai 7 cek deterministik, lalu melampirkan Groth16 proof
yang dibuat lokal dengan circuit resmi — persis seperti yang diminta halaman
Build ("your agent receives a task, makes a decision, and writes its own
zero-knowledge proof").

> Status: kode + test lokal selesai (36/36 PASS, 15 Nov 2026). **Belum
> didaftarkan, belum di-deploy.** Pendaftaran & deploy butuh langkah Adimas
> (lihat bawah). Tidak ada wallet/keys yang disentuh di repo ini.

## Cara kerja

```
Platform --POST /agent (HMAC)--> server.js
  1. Verifikasi HMAC atas raw body (header x-agent-games-signature)
  2. decide(): 7 cek -> APPROVE/REJECT + reason_code
  3. generateProof(): fullProve lokal (snarkjs + gatekeeper.wasm/zkey)
  4. Respon JSON + header x-agent-games-signature (HMAC atas raw body)
```

### Logika keputusan (lib/decision.js)

| reason_code | Kondisi | Keputusan |
|---|---|---|
| `VALID_CONDITION` | semua cek lolos | APPROVE |
| `VK_SUBSTITUTION` | `proof_vk != registered_vk` | REJECT |
| `THRESHOLD_MISMATCH` | `public_balance < minimum` | REJECT |
| `PROOF_REUSED` | `proof_tx` sudah pernah di-APPROVE (seen-set) | REJECT, tanpa proof |
| `EXPIRED_CONDITION` | `current_block > expiry_block` | REJECT |
| `RECIPIENT_MISMATCH` | `recipient != condition_recipient` | REJECT |
| `AMOUNT_OVERFLOW` | `amount > max_transfer` | REJECT |
| `INVALID_INPUT` | field hilang / bukan angka / alamat tidak valid | REJECT, tanpa proof |

Prioritas mengikuti urutan "trap encyclopedia" di halaman event. Fail closed:
kalau ragu, REJECT. Skor: benar +12, salah approve −6, salah reject −3,
timeout −2, proof hilang/invalid −2.

### Proof (lib/proof.js)

Circuit resmi gatekeeper (`vkHash 0x6b79c6…d77b0`), 13 sinyal input.
Layout public signals (13) — **diverifikasi dengan probe, 15 Nov 2026**:

```
[0]  Poseidon([salt, taskId])   — replay-binding commitment
[1]  registeredVkHash  [2] proofVkHash  [3] minimum
[4]  publicBalance     [5] expiryBlock  [6] currentBlock
[7]  recipient         [8] conditionRecipient
[9]  amount            [10] maxTransfer
[11] decision          [12] taskId
```

Proof generation ~300–400 ms di VM ini (jauh di bawah batas 60 detik).
Circuit bersifat strict: `fullProve` **gagal** untuk keputusan yang salah
(APPROVE pada trap, atau REJECT pada input yang sepenuhnya valid) — sudah
dites dan dikonfirmasi. Untuk `PROOF_REUSED`, proof sengaja tidak dilampirkan
(halaman event: "PROOF_REUSED tasks have no proof to submit").

## Jalankan lokal

```bash
npm install
npm run download-circuits   # atau: download sudah ada di circuits/
cp .env.example .env         # isi AGENT_GAMES_HMAC_SECRET untuk mode produksi
npm start                    # :3000, GET /health, POST /agent
npm test                     # test integrasi (36 checks)
```

Env vars: `PORT` (default 3000), `AGENT_GAMES_HMAC_SECRET` (wajib di
`NODE_ENV=production`, server menolak start tanpanya), `CIRCUIT_WASM` /
`CIRCUIT_ZKEY` / `CIRCUIT_VK` (default `circuits/`), `ZKVERIFY_RPC_URL`
(opsional, lihat "Cek on-chain" di bawah).

File circuit di `circuits/` (bukan bagian dari logika — download ulang
dengan `scripts/download-circuits.sh` bila perlu):

| file | ukuran | SHA-256 |
|---|---|---|
| gatekeeper.wasm | 1.755.820 | `be00aefe…92764f` |
| gatekeeper_final.zkey | 309.750 | `adfe95a4…01af80d` |
| verification_key.json | — | diekstrak dari zkey (`nPublic: 13`) |

## Deploy

Butuh host Node.js + **HTTPS publik** (platform hanya menerima HTTPS).
Pilihan umum: Fly.io / Railway / Render / VPS. Contoh (Fly.io):

```bash
fly launch --no-deploy && fly deploy   # lalu set secrets:
fly secrets set AGENT_GAMES_HMAC_SECRET=<secret-dari-dashboard>
```

Pastikan endpoint lolos health check platform dan merespon < 60 detik.
Perhatian: VM ini (tempat kode ini dibuat) bersifat ephemeral — jangan
jadikan URL dari VM ini sebagai endpoint kompetisi.

## Registrasi (langkah Adimas — butuh akun X / wallet)

1. Buka https://agentgames.zkverify.io/register, sign-in dengan X atau wallet.
2. Isi handle `Frozen008`, negara, bio; wallet `0x514e783bBa5a9087E51D09B1D7aED45F7a11DAd9`
   (wajib untuk klaim hadiah VFY).
3. Daftarkan agent: nama `Frozen008`, centang Proof Gatekeeper, isi
   Repository URL dengan repo GitHub publik berisi kode ini, isi Agent Endpoint
   dengan URL HTTPS hasil deploy.
4. Di dashboard: **Rotate Secret** → salin secret itu ke env
   `AGENT_GAMES_HMAC_SECRET` di host deploy (jangan commit ke repo).
5. Lewati health check → signed preflight → minimal 1 practice task.
6. Round 03 dimulai 15 Nov 17:30 WIB (4PM IST). Pendaftaran/entry terkunci
   saat round berjalan — daftar sebelum round dibuka.

## Yang masih belum pasti (jangan diklaim sudah beres)

1. **Nama header HMAC incoming.** Halaman Build menamai header
   `x-agent-games-signature` untuk *response*; nama header request tidak
   didokumentasikan. Implementasi memakai nama yang sama untuk keduanya.
   Bila preflight gagal, cek dashboard/dokumentasi untuk nama pastinya.
2. **Format health check.** Diasumsikan `GET /health` (dan `GET /`) dengan
   respon `{"status":"ok"}`. Bila platform memanggil path/metode lain,
   sesuaikan `server.js`.
3. **Encoding `taskId`.** Circuit menerima field element apa pun; kami memakai
   `keccak256(taskId) mod p`. Platform mungkin memakai encoding lain saat
   membandingkan `publicSignals[12]` — tidak ada dokumentasi resmi soal ini.
   Bila proof ditolak platform padahal `snarkjs verify` OK, encoding inilah
   tersangka pertama.
4. **Salt.** Private input; kami menurunkan secara deterministik dari
   `keccak256("frozen008-agent-games-salt:" + taskId)`. Nilai apa pun valid
   secara kriptografis (komitmen `Poseidon([salt, taskId])` dihitung circuit
   dari input kita).
5. **Cek on-chain proof (`lib/chain.js`) — TIDAK diimplementasikan.**
   RPC publik zkVerify (`rpc.zkverify.io`, `api.zkverify.io`) tidak terjangkau
   dari VM ini (dites 15 Nov 2026), dan Kurier adalah API submission berbayar
   (butuh API key) tanpa endpoint baca publik yang ditemukan. Keputusan tetap
   memakai 6 dari 7 cek lokal; verifikasi inklusi `proof_tx` di mainnet
   adalah gap yang diketahui. **Jangan pura-pura ini terverifikasi.**
   Bila RPC/key tersedia, implementasikan lookup-nya di `lib/chain.js`.
6. **Seen-set `PROOF_REUSED`.** Kami menandai `proof_tx` sebagai "sudah
   dipakai" hanya saat kami APPROVE (bacaan literal "already accepted in a
   previous task"), dan terpisah per mode (`competition`/`practice`).
7. **Steal the VFY tidak dibangun.** Track itu butuh strategy commitment +
   proof kebijakan per turn, dan Swiss Round 1 sudah dibuka 13 Nov (entry
   mungkin terkunci). Repo ini hanya Proof Gatekeeper.

## File

```
server.js                  HTTP server (POST /agent, GET /health, GET /)
lib/decision.js            logika 7 cek (murni, unit-testable)
lib/proof.js               buildCircuitInput / generateProof / verifyProof
lib/store.js               seen-set persisten (data/seen.json)
lib/chain.js               cek on-chain — stub jujur (belum terimplementasi)
scripts/download-circuits.sh
circuits/                  gatekeeper.wasm, gatekeeper_final.zkey, verification_key.json
test/local-test.js         36 checks (HTTP + proof + strictness + benchmark)
README.md  .env.example  .gitignore  package.json
```

## Test (15 Nov 2026, hasil)

`npm test` → **36 passed, 0 failed**, antara lain:

- VALID → APPROVE + proof terverifikasi snarkjs; round-trip 939 ms.
- Tiap trap (6) → REJECT + reason_code benar + proof decision-0 terverifikasi.
- PROOF_REUSED → REJECT tanpa field proof; BAD HMAC → 401; tipe salah → 400.
- Circuit menolak APPROVE pada trap dan REJECT pada input valid (fullProve gagal).
- Benchmark proof: ~300–370 ms (batas 60.000 ms).
