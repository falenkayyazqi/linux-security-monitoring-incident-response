# Pemantauan Autentikasi SSH dan Deteksi Brute-Force

**Language:** Bahasa Indonesia | [English Version](detection-analysis.md)

## Tujuan

Membangun log monitoring sederhana menggunakan Python untuk menganalisis `/var/log/auth.log` dan mendeteksi pola brute-force authentication pada layanan SSH.

Monitoring difokuskan pada:

- Failed SSH authentication
- Successful SSH authentication
- Brute-force attempt berdasarkan jumlah kegagalan dalam sliding time window
- Sudo activity sebagai supporting authentication/security telemetry

## Konfigurasi Deteksi

- Log source: `/var/log/auth.log`
- Threshold: 5 percobaan autentikasi gagal
- Time window: 5 menit
- Tracking key: source ip + username
- Analysis period:
  - Mulai: `2026-09-25T17:59:00+07:00`
  - Selesai: `2026-09-25T18:04:30+07:00`

## Simulasi

Aktivitas autentikasi dihasilkan dari VM Kali Linux:

- Source IP: `192.168.82.130`
- Target Ubuntu Server IP: `192.168.82.129`

Simulasi menghasilkan percobaan autentikasi SSH yang gagal terhadap username `admin`, `root`, dan `test`.

Akun `test` menerima 6 percobaan kata sandi yang gagal dalam periode analisis, sehingga detektor mencapai threshold yang telah dikonfigurasi. Simulasi juga menghasilkan satu autentikasi SSH yang berhasil menggunakan public key untuk akun `user`.

## Hasil Deteksi

Detektor memproses periode analisis yang ditentukan dan menghasilkan:

- Login gagal: 10
- Login diterima: 1
- Perintah sudo: 0
- Alert yang dihasilkan: 1

Alert yang dihasilkan adalah **`BRUTE-FORCE ATTEMPT`** dengan detail:

- Source IP: `192.168.82.130`
- Username target: `test`
- Waktu deteksi: `2026-09-25T18:01:56.577144+07:00`
- Percobaan gagal dalam 5 menit: `5`

## Analisis Autentikasi

Autentikasi yang gagal berkaitan dengan percobaan autentikasi menggunakan kata sandi. Autentikasi berhasil memiliki atribut berikut:

- Username: `user`
- Source IP: `192.168.82.130`
- Metode autentikasi: `publickey`

Karena itu, detektor tidak mengklasifikasikan login public-key yang berhasil sebagai kata sandi yang berhasil di.

## Evidence

Bukti pendukung disimpan di folder `evidence/`:

- `ssh-auth-log.txt` - Autentikasi SSH yang difilter dari periode simulasi
- `monitor-output.txt` - output terminal dari detektor Python
- `alerts.json` - hasil deteksi
- `sudo-activity.txt` - catatan aktivitas sudo selama periode analisis

## Batasan

Ini merupakan latihan host-based monitoring sederhana dan bukan pengganti SIEM atau IDS/IPS produksi. Detektor menganalisis log autentikasi lokal dan menerapkan aturan berbasis threshold. Namun ini belum menyediakan:

- Pengumpulan log terpusat
- Alerting persisten
- Respons otomatis
- Analisis reputasi IP
- Korelasi lintas host
- Deteksi perilaku tingkat lanjut

## Pertimbangan Keamanan

Autentikasi SSH menggunakan kata sandi yang hanya diaktifkan sementara untuk simulasi lab terkontrol. Setelah simulasi, konfigurasi SSH asli dipulihkan dan divalidasi dengan `PasswordAuthentication no`. Status layanan SSH juga diverifikasi tetap aktif setelah konfigurasi dipulihkan.

## Kesimpulan

Lab ini menunjukkan alur kerja dasar SOC:

1. Menghasilkan aktivitas autentikasi terkontrol.
2. Mengumpulkan log autentikasi.
3. Mem-parsing aktivitas SSH yang relevan.
4. Mengorelasikan kegagalan berdasarkan source IP dan username.
5. Menerapkan aturan deteksi berbasis ambang batas.
6. Menghasilkan kumpulan alert.
7. Menyimpan evidence pendukung.
8. Memulihkan server ke konfigurasi yang telah diperkuat.

