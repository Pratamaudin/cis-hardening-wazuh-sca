# CIS Hardening of a Vulnerable Active Directory Lab with Wazuh SCA

Mengaudit sebuah Domain Controller yang sengaja dibuat rentan menggunakan
**Wazuh Security Configuration Assessment (SCA)** terhadap **CIS Microsoft
Windows Server 2022 Benchmark v2.0.0**, memperbaiki temuan yang menutup jalur
serangan aktif, lalu membuktikan hasilnya dari dua sisi: **serangan** dan
**compliance**.

Proyek ini adalah kelanjutan dari lab deteksi serangan (Kerberoasting,
AS-REP Roasting, Password Spraying) pada SIEM yang sama. Busur ceritanya:

> **Serang → Audit → Perbaiki → Buktikan**

---

## 1. Ringkasan

| | |
|---|---|
| **Target** | DC01 — Windows Server 2022 Standard (Build 20348) |
| **Tool** | Wazuh SCA |
| **Policy** | CIS Microsoft Windows Server 2022 Benchmark v2.0.0 (`cis_win2022.yml`) |
| **Temuan diperbaiki** | #27061 — Encryption types allowed for Kerberos |
| **Metode remediasi** | Registry (PowerShell) untuk iterasi cepat; GPO sebagai pendekatan produksi |
| **Hasil** | RC4 dimatikan → tiket Kerberos beralih `0x17` (RC4) → `0x12` (AES256); check #27061 Failed → Passed |

---

## 2. Baseline — kondisi awal (sebelum hardening)

Scan pertama dijalankan pada mesin dalam kondisi default-lab yang rentan.

| Metrik | Nilai |
|---|---:|
| **Skor keseluruhan** | **29%** |
| Passed | 104 |
| Failed | 254 |
| Not applicable | 1 |
| Total check | 359 |

> _Scan selesai: 26 Okt 2026, 13:49_
> _Screenshot: `screenshots/sca-baseline.png`_

Skor 29% mencerminkan konfigurasi lab yang memang dilemahkan untuk keperluan
latihan serangan. 254 kegagalan menjadi kumpulan temuan mentah; proyek ini
tidak memperbaiki semuanya, melainkan menerapkan **prioritas berbasis risiko**
— memperbaiki temuan yang menutup jalur serangan nyata yang sudah
didemonstrasikan lebih dulu.

---

## 3. Pemetaan temuan ke serangan

Tiga temuan CIS teridentifikasi relevan dengan serangan di lab. Satu
diperbaiki dan dibuktikan penuh pada proyek ini; dua sisanya didokumentasikan
sebagai _future work_ (bagian 7).

| CIS ID | Temuan | Jalur serangan terkait | Status |
|---|---|---|---|
| **27061** | Encryption types allowed for Kerberos (RC4 diizinkan) | **Kerberoasting** — tiket RC4 (`0x17`) mudah di-crack | ✅ Diperbaiki & dibuktikan |
| 27063 | LAN Manager authentication level (LM/NTLMv1 diizinkan) | Serangan berbasis NTLM / credential sniffing | ⏳ Future work |
| 27200 | Delegation of non-exportable credentials (Credential Guard) | Pencurian kredensial saat sesi RDP | ⏳ Future work |

---

## 4. Remediasi — #27061

Semua perubahan diterapkan di **DC01**.

**Masalah.** Registry `SupportedEncryptionTypes` tidak diset, sehingga Domain
Controller memakai default yang masih mengizinkan **RC4**. Akibatnya DC
menerbitkan service ticket berenkripsi RC4 (`0x17`) yang bisa di-crack offline
— inti dari serangan Kerberoasting. Kerentanan diperkuat oleh akun `svc-sql`
yang di-override khusus RC4 (`msDS-SupportedEncryptionTypes = 4`) untuk
keperluan demo serangan.

**Target CIS.** Hanya izinkan AES128 + AES256 (+ future), buang RC4 dan DES.

### 4.1 Matikan RC4 di level Domain Controller

```powershell
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "SupportedEncryptionTypes" -Value 2147483640 -Type DWord
```

Nilai `2147483640` (`0x7FFFFFF8`) adalah **bitmask**: AES128 + AES256 + semua
tipe future **menyala**, sedangkan bit RC4 (`0x4`) dan DES (`0x1`, `0x2`)
**padam**. Mematikan bit RC4 inilah inti perbaikannya.

### 4.2 Kembalikan `svc-sql` ke kebijakan domain

Override per-akun mengalahkan kebijakan DC, jadi override RC4 pada akun harus
dihapus agar akun ikut aturan AES:

```powershell
Set-ADUser svc-sql -Clear "msDS-SupportedEncryptionTypes"
```

### 4.3 Reboot

Kerberos meng-cache tiket di memori. Reboot (atau `klist purge`) membuang
tiket RC4 lama agar permintaan berikutnya dibuat ulang dengan aturan baru.

```powershell
Restart-Computer -Force
```

### Path GPO (pendekatan produksi)

`Computer Configuration → Policies → Windows Settings → Security Settings →
Local Policies → Security Options → Network security: Configure encryption
types allowed for Kerberos` → pilih AES128_HMAC_SHA1, AES256_HMAC_SHA1,
Future encryption types.

---

## 5. Pembuktian #1 — dari sisi serangan

Serangan Kerberoasting yang sama (permintaan TGS untuk SPN `svc-sql`)
dijalankan ulang sesudah hardening, lalu enkripsi tiketnya diperiksa pada
event **4769** di Wazuh.

| | Sebelum hardening | Sesudah hardening |
|---|---|---|
| `ticketEncryptionType` | `0x17` (RC4) | **`0x12` (AES256)** |
| Rule 100100 (deteksi TGS RC4) | Terpicu — alert "Kerberoasting terdeteksi" | **Tidak terpicu** — tiket bukan lagi RC4 |
| Kesulitan crack offline | Rendah (password lemah tembus cepat) | Sangat tinggi (AES256 praktis tak bisa di-brute force) |

Satu-satunya variabel yang berubah adalah enkripsi tiket — SPN, event ID, dan
agent identik. Permintaan tiket sesudah hardening tercatat sebagai _logon
biasa_, bukan alert Kerberoasting, karena rule 100100 hanya cocok dengan
`0x17`. Kerentanan tertutup, bukan deteksi yang rusak.

> _Screenshot: `screenshots/before-after-comparison.png`_
> _(menampilkan event `0x17` lama yang memicu rule 100100, berdampingan dengan event `0x12` baru yang tidak memicu alert)_

---

## 6. Pembuktian #2 — dari sisi compliance (re-scan SCA)

SCA dijalankan ulang sesudah remediasi.

| Metrik | Baseline | Sesudah | Perubahan |
|---|---:|---:|---:|
| Skor keseluruhan | 29% | 29% | ±0 |
| Passed | 104 | 105 | +1 |
| Failed | 254 | 253 | −1 |

> _Scan selesai: 26 Okt 2026, 14:27_
> _Screenshot: `screenshots/sca-after.png`_

**Check #27061: Failed → Passed.** SCA membaca registry, menemukan nilai
`2147483640`, dan menyatakannya sesuai standar CIS.

**Catatan analitis.** Skor keseluruhan hampir tak bergerak karena hanya 1 dari
254 temuan yang diperbaiki — terlalu kecil untuk menggeser persentase bulat.
Ini disajikan apa adanya secara sengaja: nilai proyek ini bukan pada mengejar
skor tinggi, melainkan pada **kedalaman satu temuan yang dikejar tuntas lintas
serangan dan audit**. Memperbaiki temuan yang menutup jalur serangan aktif
lebih bermakna daripada mematikan ratusan setting tanpa memahami dampaknya.

---

## 7. Future work

Dua temuan berikut sudah teridentifikasi dan disiapkan remediasinya, namun
belum diterapkan pada iterasi ini:

- **#27063 — LAN Manager authentication level.** Paksa NTLMv2 saja
  (`LmCompatibilityLevel = 5`), tolak LM & NTLMv1.
- **#27200 — Delegation of non-exportable credentials.** Aktifkan proteksi
  kredensial (`AllowProtectedCreds = 1`).

Pertimbangan sebelum menerapkan di produksi:
- Pastikan semua akun service sudah memiliki kunci AES (reset password bila
  akun lama) sebelum RC4 dimatikan total, agar autentikasi tidak terputus.
- Uji aplikasi/sistem legacy yang mungkin masih bergantung pada RC4 atau NTLM.
- Terapkan via GPO agar konsisten dan tahan perubahan lokal.

---

## 8. Catatan metodologi

- **Registry vs GPO.** Di lab ini remediasi diterapkan lewat registry
  (PowerShell) untuk iterasi cepat. Di Active Directory produksi, setting yang
  sama seharusnya lewat **Group Policy** karena otomatis terdistribusi,
  konsisten, dan tahan terhadap perubahan lokal.
- **Prioritas berbasis risiko.** Dengan 254 temuan, pendekatan yang dipilih
  adalah menutup jalur serangan nyata lebih dulu, bukan mengejar skor 100%
  tanpa konteks.
- **Compliance mapping.** Tiap temuan CIS juga terpetakan ke standar lain
  (NIST 800-53, ISO 27001, PCI DSS, HIPAA) — lihat bagian _Compliance_ pada
  detail check di dashboard Wazuh.

---

## 9. Ringkasan siklus

| Fase | Yang dilakukan | Bukti |
|---|---|---|
| **Serang** | Kerberoasting terhadap `svc-sql` | Alert rule 100100, tiket `0x17` |
| **Audit** | SCA vs CIS Benchmark | Skor 29%, #27061 Failed |
| **Perbaiki** | Matikan RC4 (bitmask), clear override akun, reboot | `SupportedEncryptionTypes = 2147483640` |
| **Buktikan** | Re-attack + re-scan | Tiket `0x12`, rule sunyi, #27061 Passed |

---

## 10. Struktur repo

```
.
├── README.md
├── screenshots/
│   ├── sca-baseline.png              # skor 29%, baseline
│   ├── before-after-comparison.png   # event 0x17 (alert) vs 0x12 (no alert)
│   └── sca-after.png                 # #27061 Passed, skor sesudah
└── remediation/
    └── harden-dc01.ps1               # perintah fix #27061 (bagian 4)
```
