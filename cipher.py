"""
================================================================================
MODUL KRIPTOGRAFI MANUAL: ALGORITMA RC4 (RIVEST CIPHER 4)
Mata Kuliah: Keamanan Informasi (KI)
================================================================================
CATATAN PENTING:
Modul ini murni diimplementasikan secara manual DARI NOL (from scratch).
TIDAK MENGGUNAKAN library kriptografi pihak ketiga (seperti pycryptodome, 
cryptography, atau hashlib).

RC4 adalah algoritma Symmetric Stream Cipher yang bekerja byte-per-byte.
Terdiri dari 2 fase utama:
1. KSA (Key-Scheduling Algorithm) : Inisialisasi & pengacakan State Array S (0..255).
2. PRGA (Pseudo-Random Generation Algorithm) : Pembangkitan keystream tak hingga.

Enkripsi & Dekripsi pada stream cipher adalah operasi simetris menggunakan XOR:
- Ciphertext = Plaintext XOR Keystream
- Plaintext  = Ciphertext XOR Keystream (karena (A XOR B) XOR B = A)
================================================================================
"""

def ksa(key_bytes: bytes) -> list[int]:
    """
    Key-Scheduling Algorithm (KSA)
    Fungsi ini menginisialisasi array permutasi S berukuran 256 elemen (0 s/d 255),
    lalu mengacak urutan S berdasarkan byte-byte dari Kunci (Key).
    """
    key_length = len(key_bytes)
    if key_length == 0:
        raise ValueError("Kunci (key) tidak boleh kosong!")

    # 1. Inisialisasi larik S dengan nilai 0 sampai 255
    S = list(range(256))

    # 2. Pengacakan larik S berdasarkan key
    j = 0
    for i in range(256):
        # Rumus KSA: j = (j + S[i] + Key[i mod key_length]) mod 256
        j = (j + S[i] + key_bytes[i % key_length]) % 256
        # Tukar nilai S[i] dan S[j] (swap)
        S[i], S[j] = S[j], S[i]

    return S


def prga(S: list[int]):
    """
    Pseudo-Random Generation Algorithm (PRGA)
    Generator yang menghasilkan aliran byte acak (keystream) satu per satu.
    Menggunakan generator Python (yield) untuk efisiensi memori.
    """
    # Buat salinan S agar array aslinya tidak termodifikasi di luar
    S_box = list(S)
    i = 0
    j = 0

    while True:
        # Rumus PRGA:
        i = (i + 1) % 256
        j = (j + S_box[i]) % 256
        # Tukar nilai S[i] dan S[j]
        S_box[i], S_box[j] = S_box[j], S_box[i]

        # Ambil byte keystream K
        t = (S_box[i] + S_box[j]) % 256
        K = S_box[t]
        yield K


def rc4_process(data_bytes: bytes, key_str: str) -> bytes:
    """
    Fungsi inti RC4 yang melakukan XOR antara data_bytes dengan keystream.
    Fungsi ini digunakan untuk ENKRIPSI maupun DEKRIPSI karena sifat XOR yang simetris.
    """
    key_bytes = key_str.encode('utf-8')
    S = ksa(key_bytes)
    keystream = prga(S)

    result = bytearray()
    for byte in data_bytes:
        # Operasi XOR antara 1 byte data dengan 1 byte keystream
        keystream_byte = next(keystream)
        result.append(byte ^ keystream_byte)

    return bytes(result)


def encrypt(plaintext: str, key: str) -> str:
    """
    Fungsi Enkripsi:
    1. Mengubah teks asli (plaintext) menjadi representasi byte UTF-8.
    2. Menghasilkan ciphertext byte menggunakan algoritma RC4.
    3. Mengubah hasil byte ke representasi HEX (heksadesimal) agar aman 
       ditransmisikan melalui socket jaringan sebagai teks biasa.
    
    Contoh: "Halo" -> "4f2a9c1e"
    """
    data_bytes = plaintext.encode('utf-8')
    cipher_bytes = rc4_process(data_bytes, key)
    # Ubah ke string heksadesimal (misal: b'\x4f\x2a' -> '4f2a')
    return cipher_bytes.hex()


def decrypt(ciphertext_hex: str, key: str) -> str:
    """
    Fungsi Dekripsi:
    1. Mengubah string HEX dari transmisi jaringan kembali menjadi byte asli.
    2. Menjalankan proses RC4 dengan keystream yang sama (menghasilkan plaintext byte).
    3. Meng-decode byte kembali menjadi teks string UTF-8.
    """
    try:
        cipher_bytes = bytes.fromhex(ciphertext_hex.strip())
        plain_bytes = rc4_process(cipher_bytes, key)
        # Menggunakan errors='backslashreplace' agar jika kunci salah,
        # byte acak ditampilkan dalam format escape \xNN tanpa crash di konsol Windows (cp1252)
        return plain_bytes.decode('utf-8', errors='backslashreplace')
    except ValueError as e:
        return f"[ERROR DEKRIPSI: Format Hex Tidak Valid ({e})]"


if __name__ == "__main__":
    # Pengujian mandiri lokal
    print("=== PENGUJIAN MANDIRI ALGORITMA RC4 MANUAL ===")
    test_key = "KunciRahasiaKI2026"
    test_msg = "Halo Dunia! Ini pesan rahasia tugas Keamanan Informasi."

    print(f"Key           : {test_key}")
    print(f"Plaintext     : {test_msg}")

    cipher_hex = encrypt(test_msg, test_key)
    print(f"Ciphertext HEX: {cipher_hex}")

    decrypted = decrypt(cipher_hex, test_key)
    print(f"Hasil Dekripsi: {decrypted}")

    assert decrypted == test_msg, "Uji coba gagal: Plaintext dan hasil dekripsi tidak cocok!"
    print("\n[OK] Algoritma bekerja 100% sempurna!")
