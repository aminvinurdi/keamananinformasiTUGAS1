"""
================================================================================
MODUL KRIPTOGRAFI MANUAL: ALGORITMA DES (DATA ENCRYPTION STANDARD)
Mata Kuliah: Keamanan Informasi (KI)
================================================================================
CATATAN PENTING:
Modul ini murni diimplementasikan secara manual DARI NOL (from scratch).
TIDAK MENGGUNAKAN library kriptografi pihak ketiga (seperti pycryptodome, 
cryptography, atau hashlib).

Karakteristik DES:
- Block Cipher Simetris: Bekerja pada blok 64-bit (8 byte).
- Kunci: 64-bit (56-bit efektif + 8-bit paritas).
- Struktur: Feistel Network sebanyak 16 Putaran (Rounds).
- Padding: Standar PKCS#7 agar teks dengan panjang berapapun dapat diproses.
================================================================================
"""

# ==============================================================================
# TABEL STANDAR DES (FIPS PUB 46-3)
# ==============================================================================

# 1. Initial Permutation (IP) - Permutasi Awal 64 bit
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# 2. Final Permutation (IP Inverse / IP-1) - Permutasi Akhir 64 bit
IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
]

# 3. Permuted Choice 1 (PC-1) - Mengubah 64-bit key menjadi 56-bit (C0 dan D0)
PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
]

# 4. Tabel Pergeseran Kiri (Left Shift Schedule) untuk 16 Putaran
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 5. Permuted Choice 2 (PC-2) - Mengkompres 56-bit menjadi Subkey 48-bit per round
PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# 6. Expansion Table (E) - Memperluas 32-bit R menjadi 48-bit
EXPANSION = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
]

# 7. S-Boxes (8 Kotak Substitusi 4x16)
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# 8. Permutation Table (P-Box) - Mengacak 32-bit output dari S-Boxes
P_BOX = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
]

# ==============================================================================
# FUNGSI-FUNGSI HELPER MANIPULASI BIT
# ==============================================================================

def bytes_to_bits(data: bytes) -> list[int]:
    """Mengubah bytearray/bytes menjadi list integer bit (0 dan 1)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits: list[int]) -> bytes:
    """Mengubah list integer bit (0 dan 1) kembali menjadi bytes."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte_val = 0
        for bit in bits[i:i+8]:
            byte_val = (byte_val << 1) | bit
        out.append(byte_val)
    return bytes(out)

def permute(bits: list[int], table: list[int]) -> list[int]:
    """Melakukan permutasi bit berdasarkan tabel indeks 1-based standar DES."""
    return [bits[pos - 1] for pos in table]

def xor_bits(a: list[int], b: list[int]) -> list[int]:
    """Melakukan operasi bitwise XOR antara dua list bit."""
    return [x ^ y for x, y in zip(a, b)]

def left_shift(bits: list[int], n: int) -> list[int]:
    """Melakukan cyclic left shift sebanyak n posisi."""
    return bits[n:] + bits[:n]

# ==============================================================================
# KEY SCHEDULING (PEMBANGKITAN 16 SUBKEY)
# ==============================================================================

def normalize_key(key: str) -> bytes:
    """
    Memastikan kunci berukuran tepat 8 byte (64 bit) untuk DES.
    Jika kurang dari 8 byte, akan ditambah padding null bytes.
    Jika lebih dari 8 byte, akan dipotong menjadi 8 byte pertama.
    """
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 8:
        key_bytes = (key_bytes + b'\x00' * 8)[:8]
    else:
        key_bytes = key_bytes[:8]
    return key_bytes

def generate_subkeys(key_bytes: bytes) -> list[list[int]]:
    """
    Menghasilkan 16 subkey 48-bit (K1 s/d K16) dari kunci 64-bit menggunakan:
    1. PC-1 (64 bit -> 56 bit: C0 28 bit, D0 28 bit)
    2. 16 putaran pergeseran bit (Left Shift Schedule)
    3. PC-2 (56 bit -> Subkey 48 bit)
    """
    key_bits = bytes_to_bits(key_bytes)
    
    # 1. Terapkan PC-1
    permuted_key = permute(key_bits, PC1)
    C = permuted_key[:28]
    D = permuted_key[28:]

    subkeys = []
    # 2. Lakukan 16 Putaran Pembangkitan Subkey
    for shift in SHIFT_SCHEDULE:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        # Gabungkan C dan D (56 bit), lalu kompres ke 48 bit dengan PC-2
        CD = C + D
        round_key = permute(CD, PC2)
        subkeys.append(round_key)

    return subkeys

# ==============================================================================
# FUNGSI FEISTEL f(R, K) & PROSES BLOK DES
# ==============================================================================

def feistel(R: list[int], K: list[int]) -> list[int]:
    """
    Fungsi Feistel f(R, K):
    1. Expansion (E): Memperluas R (32 bit) menjadi 48 bit.
    2. XOR dengan Subkey K (48 bit).
    3. Substitusi S-Box: 8 S-Box masing-masing mengubah 6 bit -> 4 bit (Total 32 bit).
    4. Permutasi P-Box: Mengacak 32 bit hasil S-Box.
    """
    # 1. Expansion
    expanded = permute(R, EXPANSION)
    
    # 2. XOR dengan Subkey putaran
    xored = xor_bits(expanded, K)

    # 3. Substitusi S-Boxes
    s_output = []
    for i in range(8):
        block_6bit = xored[i * 6 : (i + 1) * 6]
        # Baris ditentukan oleh bit ke-1 dan bit ke-6
        row = (block_6bit[0] << 1) | block_6bit[5]
        # Kolom ditentukan oleh 4 bit di tengah (bit 2, 3, 4, 5)
        col = (block_6bit[1] << 3) | (block_6bit[2] << 2) | (block_6bit[3] << 1) | block_6bit[4]
        
        val_4bit = S_BOXES[i][row][col]
        # Ubah integer 4-bit ke 4 bit individu
        for b in range(3, -1, -1):
            s_output.append((val_4bit >> b) & 1)

    # 4. Permutasi P-Box
    return permute(s_output, P_BOX)

def des_process_block(block_64: bytes, subkeys: list[list[int]]) -> bytes:
    """
    Memproses satu blok 64-bit (8 byte) melalui 16 putaran Feistel Network.
    - Untuk Enkripsi : subkeys diurutkan K1 s/d K16
    - Untuk Dekripsi : subkeys diurutkan terbalik K16 s/d K1
    """
    bits = bytes_to_bits(block_64)

    # 1. Initial Permutation (IP)
    ip_bits = permute(bits, IP)
    L = ip_bits[:32]
    R = ip_bits[32:]

    # 2. 16 Rounds Feistel Network
    for K in subkeys:
        f_result = feistel(R, K)
        next_R = xor_bits(L, f_result)
        L = R
        R = next_R

    # 3. Pre-Output Swap (R16 + L16)
    combined = R + L

    # 4. Final Permutation (IP Inverse)
    final_bits = permute(combined, IP_INV)
    return bits_to_bytes(final_bits)

# ==============================================================================
# PADDING PKCS#7 & INTERFACE UTAMA
# ==============================================================================

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """
    Menambahkan padding PKCS#7 agar panjang data menjadi kelipatan 8 byte.
    Contoh: jika data kurang 3 byte, tambahkan 3 byte berisi nilai 0x03.
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    """Menghapus padding PKCS#7 setelah dekripsi."""
    if not data:
        raise ValueError("Data kosong tidak memiliki padding yang valid")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Padding PKCS#7 tidak valid (panjang diluar batas 1-8)")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Bita padding PKCS#7 tidak cocok")
    return data[:-pad_len]

def encrypt(plaintext: str, key: str) -> str:
    """
    Fungsi Enkripsi DES Manual:
    1. Normalisasi key menjadi 8 byte (64 bit).
    2. Pembangkitan 16 subkey (K1 s/d K16).
    3. Terapkan PKCS#7 padding ke teks plaintext.
    4. Enkripsi blok demi blok (masing-masing 8 byte) dengan Feistel Network 16 putaran.
    5. Kembalikan hasil ciphertext dalam format string Heksadesimal (Hex).
    """
    key_bytes = normalize_key(key)
    subkeys = generate_subkeys(key_bytes)
    
    data_bytes = pkcs7_pad(plaintext.encode('utf-8'))
    
    ciphertext_bytes = bytearray()
    for i in range(0, len(data_bytes), 8):
        block = data_bytes[i:i+8]
        encrypted_block = des_process_block(block, subkeys)
        ciphertext_bytes.extend(encrypted_block)
        
    return ciphertext_bytes.hex()

def decrypt(ciphertext_hex: str, key: str) -> str:
    """
    Fungsi Dekripsi DES Manual:
    1. Normalisasi key menjadi 8 byte.
    2. Pembangkitan subkey dan DIBALIK urutannya (K16 s/d K1).
    3. Decode string Hex kembali ke bytes.
    4. Dekripsi blok demi blok (masing-masing 8 byte).
    5. Hapus PKCS#7 padding dan decode ke string UTF-8.
    """
    try:
        cipher_bytes = bytes.fromhex(ciphertext_hex.strip())
        if len(cipher_bytes) % 8 != 0:
            return "[ERROR DEKRIPSI: Panjang ciphertext bukan kelipatan 8 byte]"
        
        key_bytes = normalize_key(key)
        # Urutan subkey dibalik untuk proses dekripsi Feistel Network
        subkeys_reversed = generate_subkeys(key_bytes)[::-1]

        decrypted_padded = bytearray()
        for i in range(0, len(cipher_bytes), 8):
            block = cipher_bytes[i:i+8]
            decrypted_block = des_process_block(block, subkeys_reversed)
            decrypted_padded.extend(decrypted_block)
            
        unpadded = pkcs7_unpad(bytes(decrypted_padded))
        return unpadded.decode('utf-8', errors='backslashreplace')
    except ValueError as e:
        # Jika kunci salah atau padding rusak, tampilkan pesan informatif
        return f"[GAGAL DEKRIPSI: Kunci tidak cocok atau integritas rusak ({e})]"
    except Exception as e:
        return f"[ERROR DEKRIPSI: {e}]"


if __name__ == "__main__":
    print("=== PENGUJIAN MANDIRI ALGORITMA DES MANUAL (16 ROUNDS) ===")
    test_key = "KunciDES"
    test_msg = "Halo Dunia! Ini pesan rahasia terenkripsi algoritma DES manual."

    print(f"Key           : '{test_key}'")
    print(f"Plaintext     : '{test_msg}'")

    cipher_hex = encrypt(test_msg, test_key)
    print(f"Ciphertext HEX: {cipher_hex}")

    decrypted = decrypt(cipher_hex, test_key)
    print(f"Hasil Dekripsi: '{decrypted}'")

    assert decrypted == test_msg, "Uji coba DES gagal!"
    print("\n[OK] Algoritma DES 16-Round Manual bekerja 100% sempurna!")
