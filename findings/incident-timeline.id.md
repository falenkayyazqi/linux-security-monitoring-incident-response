# Incident Timeline - SSH Brute-Force Detection and Response

**Language:** Bahasa Indonesia | [English Version](incident-timeline.md)

## Incident Summary

Simulasi terkontrol berupa serangkaian percobaan berulang autentikasi SSH dari Kali Linux ke layanan SSH pada Ubuntu. Aktivitas berasal dari jaringan lab VMware host-only dan bukan serangan nyata dari internet.

## Environment

- Attacker / simulation source: Kali Linux - `192.168.82.130`
- Target endpoint: Ubuntu (`Falen-Vmware`) - `192.168.82.129`
- Monitoring platform: Wazuh self-hosted - `192.168.82.131`
- Agent: `ubuntu-falen` (ID `001`)
- Targeted username: `user`
- Monitored service: SSH
- Timezone for Ubuntu log timestamps: WIB (`+07:00`)

## Timeline

| Waktu (WIB, 11 Oktober 2026) | Kejadian | Evidence |
|---|---|---|
| `13:41:06-13:41:08` | Ubuntu `/var/log/auth.log` mencatat 8 baris `Failed password` dari `192.168.82.130` untuk akun `user` dalam rentang beberapa detik. | `source-ip-investigation.log`, screenshot `05-ubuntu-auth-log-failed-passwords.png` |
| `13:41:07.779` | Wazuh Threat Hunting menampilkan alert rule `5763`, level `10`, dengan deskripsi SSH brute-force dan detail event menunjukkan agent `ubuntu-falen`, source IP `192.168.82.130`, username `user`, dan MITRE ATT&CK `T1110`. Alert ini dihasilkan pada percobaan gagal ke-4; `full_log` alert adalah baris `13:41:06.530677`. | Screenshot `06-wazuh-bruteforce-alert.png` dan `07-wazuh-alert-details.jpg` |
| `13:41:07` | Log Active Response memperlihatkan `firewall-drop` mulai dijalankan. Pemeriksaan firewall Ubuntu menunjukkan aturan `DROP` untuk source `192.168.82.130`. | Screenshot `08-active-response-firewall-drop.png` |
| `13:43:04-13:43:07` | Log SSH mencatat koneksi dari source yang sama mengalami `Timeout before authentication`. | `source-ip-investigation.log` |
| `13:44:08` | Log Active Response mencatat perintah `delete` untuk `firewall-drop`, 181 detik setelah block dipasang (timeout terkonfigurasi: 180 detik). | `active-responses-excerpt.log` |
| Setelah jangka timeout Active Response | Pemeriksaan akhir menunjukkan tidak ada lagi aturan block aktif dan SSH tetap aktif. Screenshot terminal Kali juga memuat output `nc` yang melaporkan TCP/22 open. | `response-verification.txt`, screenshot `04-hydra-no-valid-password.png` (screenshot ini juga memuat output `nc`) |
| Setelah simulasi | Verifikasi akhir menunjukkan SSH aktif, Wazuh agent aktif, `PasswordAuthentication no`, `MaxAuthTries 3`, dan tidak ada active block untuk source IP. | `response-verification.txt` |

**Catatan timestamp:** Timeline ini menggunakan timestamp Ubuntu dan Wazuh (WIB, UTC+7). VM Kali memakai `America/New_York` (UTC-4), 11 jam di belakang WIB, sehingga waktu Hydra (`02:40:52`-`02:42:34`) setara `13:40:52`-`13:42:34` WIB. Screenshot tidak menampilkan waktu `nc` dijalankan. Satu-satunya koneksi lanjutan dari source di `auth.log` terjadi pada `13:44:26`, setelah block dicabut, yang konsisten dengan pemeriksaan `nc` tetapi tidak dikonfirmasi oleh screenshot.

## Investigation Findings

- Source IP `192.168.82.130` sesuai dengan Kali Linux pada lab yang sama.
- Target layanan adalah SSH pada Ubuntu `192.168.82.129`, akun yang diuji adalah `user` dengan kata sandi yang salah.
- Screenshot output Hydra menunjukkan `0 valid password found`.
- 8 baris `Failed password` terlihat dalam log untuk aktivitas yang berkaitan dengan deteksi rule `5763`. Alert dihasilkan pada baris yang ke-4: `ossec.conf` pada agent mengumpulkan `/var/log/auth.log` dan `journald` sekaligus, sehingga setiap event dihitung dua kali terhadap frekuensi rule 8 (detail pada laporan insiden, Section 3).
- Tidak ditemukan `Accepted password` atau `Accepted publickey` dari source `192.168.82.130` pada potongan log investigasi untuk percobaan ini.
- Pemeriksaan akhir tidak menunjukkan koneksi block aktif, SSH dan Wazuh agent tetap aktif.
- File verifikasi dan artefak yang dikumpulkan tidak menunjukkan bukti privilege escalation yang terkait dengan simulasi. Kesimpulan ini dibatasi pada artefak dan rentang waktu yang diperiksa.

## Initial Attempt and Configuration Restoration

Percobaan awal sebelum simulasi utama hanya menyisakan satu baris `Failed password` pada file `attempt1-throttled-auth.log` dan tidak menghasilkan alert rule `5763`. Hal ini terjadi karena pembatasan OpenSSH (`MaxAuthTries` dan `PerSourcePenalties`) yang membatasi jumlah kegagalan pada percobaan awal. Kedua pembatas dilonggarkan sementara untuk simulasi deteksi terkontrol, kemudian dikembalikan.

Verifikasi akhir:

```text
SSH: active
WAZUH AGENT: active
PasswordAuthentication no
maxauthtries 3
ACTIVE RESPONSE BLOCK: No active block
```

Nilai `PerSourcePenalties` yang tercatat pada file verifikasi juga telah kembali ke nilai hardening yang digunakan pada sistem.

## Response Flow

**SSH failures → Wazuh rule 5763 → Active Response `firewall-drop` → temporary source-IP block → timeout/recovery verification → restore hardened SSH configuration.**

