# Tugas Individu Keamanan Informasi (KI)
## Simulasi Transmisi Ciphertext Komunikasi Dua Arah (DES 16-Round Manual)

Aplikasi ini adalah implementasi sistem transmisi data terenkripsi dua arah antara dua pihak (**Alice** dan **Bob**) menggunakan socket jaringan TCP dan algoritma **DES (Data Encryption Standard)** 16-Round yang **diimplementasikan manual dari nol (from scratch)** tanpa menggunakan library kriptografi instan.

---

## 📌 Kesesuaian dengan Ketentuan Tugas 

| Ketentuan | Implementasi dalam Proyek Ini |
|---|---|
| **1. Komunikasi Dua Arah** | Menggunakan arsitektur TCP Socket dengan sistem multi-threading (`threading.Thread`) di kedua sisi, memungkinkan Alice dan Bob saling mengirim dan menerima pesan secara simultan (*full-duplex*). |
| **2. Pengelolaan Key (Pre-Shared Key)** | Kunci simetris 64-bit (`KunciDES`) telah disepakati dan disimpan di memori lokal masing-masing perangkat. **Kunci sama sekali tidak pernah dikirimkan** melalui transmisi jaringan. |
| **3. Penerapan Sistem (Bukan 1 Skrip Tunggal)** | Sistem dipisah menjadi 2 aplikasi proses independen (`alice.py` dan `bob.py`). Dapat dijalankan di 2 jendela Terminal berbeda (simulasi logikal) maupun 2 komputer fisik berbeda via Wi-Fi/LAN. |
| **4. Bahasa Pemrograman Bebas** | Ditulis menggunakan **Python 3.12** dengan modul standar bawaan (`socket`, `threading`, `sys`). |
| **5. Dilarang Menggunakan Library Kriptografi** | Modul `cipher.py` mengimplementasikan algoritma standar **DES FIPS PUB 46-3** secara murni dari nol: IP, PC-1, PC-2, 16 Rounds Feistel Network, Expansion E, 8 S-Boxes, P-Box, IP Inverse, dan PKCS#7 Padding. |
| **6. Siap Demo Minggu Depan** | Output terminal dirancang informatif: menampilkan *Plaintext*, *Ciphertext Hex* yang dikirim ke kabel jaringan, *Ciphertext mentah* yang diterima, dan *Plaintext* hasil dekripsi. |

---

## 📂 Struktur Berkas

```
ki-chat-encrypted/
├── cipher.py            # Modul algoritma DES 16-Round manual lengkap (from scratch)
├── alice.py             # Program Pihak A (Server Listener / Port 5000)
├── bob.py               # Program Pihak B (Client Connector)
├── test_cipher.py       # Unit test algoritma DES manual
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
   *Tekan `Enter` untuk menggunakan konfigurasi default (Key default: `KunciDES`, Port: `5000`).*

2. **Buka Terminal 2 (Untuk Bob):**
   ```powershell
   cd C:\Users\vino\.gemini\antigravity\scratch\ki-chat-encrypted
   python bob.py
   ```
   *Tekan `Enter` untuk seluruh isian (IP default: `127.0.0.1`, Port: `5000`, Key default: `KunciDES`).*

3. **Mulai Komunikasi Dua Arah:**
   * Di Terminal Alice, ketik pesan: `halo bob` lalu tekan `Enter`.
   * Di layar Alice akan tampil ciphertext HEX hasil enkripsi 16-round DES.
   * Di layar Bob akan tampil data ciphertext yang masuk dari kabel jaringan beserta hasil dekripsinya.
   * Di Terminal Bob, ketik balasan: `ya alice` lalu tekan `Enter`.

---

## 🧪 Menjalankan Pengujian Otomatis

Untuk membuktikan ke asisten dosen bahwa kode telah teruji secara sistematis:

1. **Uji Validitas Algoritma DES:**
   ```powershell
   python test_cipher.py
   ```
   *Menguji 16 subkeys generator, PKCS#7 padding, reversibilitas berbagai panjang teks, dan simulasi kegagalan jika kunci salah.*

2. **Uji Transmisi Jaringan Dua Arah Otomatis:**
   ```powershell
   python test_integration.py
   ```
   *Mensimulasikan transmisi data soket bolak-balik dan memvalidasi bahwa hanya ciphertext yang melintas di jaringan.*

---

## 🎓 Tanya Jawab

Berikut adalah pertanyaan yang sering diajukan saat demo DES:

#### Q1: "Jelaskan bagaimana struktur algoritma DES yang kamu buat di `cipher.py`!"
> **Jawaban:** "Algoritma DES bekerja pada blok 64-bit (8 byte) menggunakan struktur **Feistel Network sebanyak 16 putaran (round)**. 
> 1. Teks awal diberikan padding **PKCS#7** agar panjangnya kelipatan 8 byte.
> 2. Blok 64-bit melalui **Initial Permutation (IP)**, lalu dibagi dua menjadi $L_0$ (32-bit kiri) dan $R_0$ (32-bit kanan).
> 3. Dalam setiap putaran dari 16 putaran:
>    - $R$ diperluas dari 32 ke 48 bit melalui tabel **Expansion (E)**.
>    - Di-XOR dengan subkey putaran tersebut ($K_i$).
>    - Dimasukkan ke **8 kotak substitusi (S-Box)** untuk dikompres kembali menjadi 32 bit.
>    - Diacak kembali dengan tabel **P-Box**.
>    - Hasilnya di-XOR dengan $L$, lalu dilakukan swap antara $L$ dan $R$.
> 4. Setelah 16 putaran, blok digabungkan kembali ($R_{16} + L_{16}$) lalu melalui **Inverse Initial Permutation ($IP^{-1}$)** untuk menghasilkan ciphertext."

#### Q2: "Bagaimana proses Key Scheduling untuk menghasilkan 16 subkey?"
> **Jawaban:** "Kunci 64-bit awalnya diproses menggunakan tabel **PC-1** yang membuang 8 bit paritas sehingga menjadi 56 bit (dibagi dua: $C_0$ 28 bit dan $D_0$ 28 bit). Pada setiap round, $C$ dan $D$ digeser ke kiri (1 atau 2 bit sesuai tabel *shift schedule*), lalu digabungkan dan dikompresi menjadi subkey 48-bit menggunakan tabel **PC-2**."

#### Q3: "Bagaimana proses dekripsi pada DES?"
> **Jawaban:** "Karena DES berbasis *Feistel Network*, algoritma proses enkripsi dan dekripsinya identik secara struktural. Perbedaannya hanya terletak pada **urutan subkey-nya yang dibalik**, yaitu dari $K_{16}$ mundur sampai $K_1$."

#### Q4: "Bagaimana jika kuncinya tidak cocok?"
> **Jawaban:** "Jika kunci penerima salah, proses 16 round Feistel akan menghasilkan plaintext acak yang rusak. Saat memeriksa byte padding PKCS#7 di akhir blok, verifikasi padding akan gagal sehingga sistem menolak pesan tersebut dengan notifikasi error."
