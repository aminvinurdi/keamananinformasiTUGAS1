# Tugas Individu Keamanan Informasi (KI)
## Simulasi Transmisi Ciphertext Komunikasi Dua Arah (Full-Duplex Encrypted Chat)

Aplikasi ini adalah implementasi sistem transmisi data terenkripsi dua arah antara dua pihak (**Alice** dan **Bob**) menggunakan socket jaringan TCP dan algoritma stream cipher **RC4 (Rivest Cipher 4)** yang **diimplementasikan manual dari nol (from scratch)** tanpa menggunakan library kriptografi instan.

---

## 📌 Kesesuaian dengan Ketentuan Tugas Dosen

| Ketentuan Dosen | Implementasi dalam Proyek Ini |
|---|---|
| **1. Komunikasi Dua Arah** | Menggunakan arsitektur TCP Socket dengan sistem multi-threading (`threading.Thread`) di kedua sisi, memungkinkan Alice dan Bob saling mengirim dan menerima pesan secara simultan (*full-duplex*). |
| **2. Pengelolaan Key (Pre-Shared Key)** | Kunci simetris telah disepakati dan disimpan di memori lokal masing-masing perangkat. **Kunci sama sekali tidak pernah dikirimkan** melalui transmisi jaringan. |
| **3. Penerapan Sistem (Bukan 1 Skrip Tunggal)** | Sistem dipisah menjadi 2 aplikasi proses independen (`alice.py` dan `bob.py`). Dapat dijalankan di 2 jendela Terminal berbeda (simulasi logikal) maupun 2 komputer fisik berbeda via Wi-Fi/LAN. |
| **4. Bahasa Pemrograman Bebas** | Ditulis menggunakan **Python 3.12** dengan modul standar bawaan (`socket`, `threading`, `sys`). |
| **5. Dilarang Menggunakan Library Kriptografi** | Modul `cipher.py` mengimplementasikan algoritma RC4 secara murni dengan logika array, operasi permutasi KSA, generator PRGA, dan operasi XOR biner tanpa modul kriptografi luar. |
| **6. Siap Demo Minggu Depan** | Output terminal dirancang informatif: menampilkan *Plaintext*, *Ciphertext Hex* yang dikirim ke kabel jaringan, *Ciphertext mentah* yang diterima, dan *Plaintext* hasil dekripsi. |

---

## 📂 Struktur Berkas

```
ki-chat-encrypted/
├── cipher.py            # Modul algoritma RC4 manual (KSA, PRGA, Encrypt, Decrypt)
├── alice.py             # Program Pihak A (Server Listener / Port 5000)
├── bob.py               # Program Pihak B (Client Connector)
├── test_cipher.py       # Unit test algoritma RC4 manual
├── test_integration.py  # Pengujian otomatis transmisi socket dua arah
└── README.md            # Dokumentasi lengkap & panduan tanya jawab demo
```

---

## 🚀 Panduan Menjalankan Demo (Langkah Demi Langkah)

### Skenario 1: Demo di Satu Laptop (Dua Terminal Berdampingan)

1. **Buka Terminal 1 (Untuk Alice):**
   ```powershell
   cd C:\Users\vino\.gemini\antigravity\scratch\ki-chat-encrypted
   python alice.py
   ```
   *Tekan `Enter` untuk menggunakan konfigurasi default (Key default: `KunciRahasiaKI2026`, Port: `5000`).*
   *Alice sekarang dalam status menunggu koneksi Bob.*

2. **Buka Terminal 2 (Untuk Bob):**
   ```powershell
   cd C:\Users\vino\.gemini\antigravity\scratch\ki-chat-encrypted
   python bob.py
   ```
   *Tekan `Enter` untuk seluruh isian (IP default: `127.0.0.1`, Port: `5000`, Key default: `KunciRahasiaKI2026`).*

3. **Mulai Komunikasi Dua Arah:**
   * Di Terminal Alice, ketik pesan: `Halo Bob, ini Alice. Pesan ini terenkripsi!` lalu tekan `Enter`.
   * Di layar Alice akan tampil ciphertext HEX yang dikirim ke kabel.
   * Di layar Bob akan tampil data ciphertext yang masuk dari kabel jaringan beserta hasil dekripsinya.
   * Di Terminal Bob, ketik balasan: `Halo Alice, pesan terbaca jelas!` lalu tekan `Enter`.
   * Di layar Alice akan tampil balasan Bob yang berhasil didekripsi.

---

### Skenario 2: Demo di Dua Laptop Fisik Berbeda (Jaringan Wi-Fi Sama)

1. Pastikan kedua laptop terhubung ke jaringan Wi-Fi / hotspot yang sama.
2. Cek IP Address Laptop Alice (buka PowerShell lalu ketik `ipconfig`, lihat IPv4 Address, misal: `192.168.1.15`).
3. Di Laptop Alice, jalankan:
   ```bash
   python alice.py
   ```
4. Di Laptop Bob, jalankan:
   ```bash
   python bob.py
   ```
   Saat diminta IP Alice, masukkan IP Laptop Alice (misal: `192.168.1.15`).

---

## 🧪 Menjalankan Pengujian Otomatis

Untuk membuktikan ke dosen bahwa kode telah teruji secara sistematis:

1. **Uji Validitas Algoritma RC4:**
   ```powershell
   python test_cipher.py
   ```
   *Menguji KSA 256 byte, reversibilitas enkripsi-dekripsi, karakter khusus, dan simulasi kegagalan jika kunci salah.*

2. **Uji Transmisi Jaringan Dua Arah Otomatis:**
   ```powershell
   python test_integration.py
   ```
   *Mensimulasikan transmisi data soket bolak-balik dan memvalidasi bahwa hanya ciphertext yang melintas di jaringan.*

---

## 🎓 Contekan Tanya Jawab (Persiapan Sesi Demo Dosen)

Berikut adalah pertanyaan yang sering diajukan dosen beserta jawaban yang tepat:

#### Q1: "Mengapa memilih algoritma RC4?"
> **Jawaban:** "RC4 adalah algoritma *Symmetric Stream Cipher* standar yang sangat efisien dan cocok untuk transmisi data *real-time*. Keunggulannya adalah dapat diimplementasikan secara manual dan bersih tanpa library luar, serta mendukung enkripsi byte-per-byte untuk semua jenis karakter dan teks tanpa batasan panjang."

#### Q2: "Bagaimana cara kerja algoritma RC4 manual di `cipher.py`?"
> **Jawaban:** "Algoritma terdiri dari 2 tahapan inti:
> 1. **KSA (Key-Scheduling Algorithm):** Menginisialisasi larik permutasi $S$ berukuran 256 byte (berisi nilai 0 sampai 255), kemudian mengacak urutannya berdasarkan byte-byte dari Kunci rahasia kita.
> 2. **PRGA (Pseudo-Random Generation Algorithm):** Membangkitkan aliran byte semu acak (*keystream*) satu demi satu.
> 3. **Operasi XOR:** Setiap byte teks asli dioperasikan secara XOR ($\oplus$) dengan 1 byte dari keystream untuk menghasilkan ciphertext:
>    $$\text{Ciphertext} = \text{Plaintext} \oplus \text{Keystream}$$
>    Untuk dekripsi, sifat XOR adalah involutif $((A \oplus B) \oplus B = A)$, sehingga ciphertext di-XOR kembali dengan keystream yang sama untuk mendapatkan teks asli."

#### Q3: "Bagaimana pengelolaan kuncinya? Apakah aman jika disadap?"
> **Jawaban:** "Sistem ini menggunakan metode *Pre-Shared Key (PSK)*. Kunci telah diketahui dan disetel terlebih dahulu di sisi Alice dan Bob sebelum komunikasi dimulai. Dalam transmisi jaringan TCP, **kunci tidak pernah dikirimkan sama sekali**. Jika ada pihak ketiga yang menyadap jaringan (*sniffing/man-in-the-middle*), mereka hanya melihat rentetan string heksadesimal acak (*ciphertext*). Tanpa kunci yang cocok, ciphertext tersebut tidak dapat dibaca."

#### Q4: "Apa yang terjadi jika pihak penerima menggunakan kunci yang berbeda?"
> **Jawaban:** "Karena sifat permutasi KSA sangat sensitif terhadap input kunci (*avalanche effect*), jika kunci berbeda 1 karakter saja, keystream yang dihasilkan PRGA akan sama sekali berbeda. Akibatnya hasil dekripsi hanya berupa karakter acak (*garbage bytes*), seperti yang telah kami buktikan pada fungsi `test_wrong_key_fails_to_decrypt` di unit test."
