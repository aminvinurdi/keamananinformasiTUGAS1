"""
================================================================================
UNIT TEST OTOMATIS: VALIDASI ALGORITMA DES MANUAL (test_cipher.py)
================================================================================
File ini menguji kebenaran matematis dan fungsionalitas dari implementasi
algoritma DES 16-Round manual.
================================================================================
"""

import unittest
from cipher import (
    encrypt, decrypt, normalize_key, generate_subkeys, 
    pkcs7_pad, pkcs7_unpad, bytes_to_bits, bits_to_bytes
)

class TestManualDES(unittest.TestCase):

    def setUp(self):
        self.key = "KunciDES"  # Kunci 8-karakter (64-bit)

    def test_basic_encryption_decryption(self):
        """Memastikan pesan biasa berhasil dienkripsi dan didekripsi kembali utuh dengan DES."""
        original = "Halo Bob, selamat siang! Ini DES."
        cipher_hex = encrypt(original, self.key)
        self.assertNotEqual(original, cipher_hex)
        decrypted = decrypt(cipher_hex, self.key)
        self.assertEqual(original, decrypted)

    def test_various_lengths_and_padding(self):
        """Menguji pesan dengan berbagai variasi panjang (1 s/d 25 karakter)."""
        for length in range(1, 25):
            msg = "A" * length
            cipher_hex = encrypt(msg, self.key)
            # Karena blok DES = 8 byte, panjang ciphertext byte harus kelipatan 8
            cipher_bytes = bytes.fromhex(cipher_hex)
            self.assertEqual(len(cipher_bytes) % 8, 0)
            decrypted = decrypt(cipher_hex, self.key)
            self.assertEqual(msg, decrypted)

    def test_special_characters_and_symbols(self):
        """Memastikan simbol, angka, dan karakter khusus didekripsi sempurna."""
        original = "Keamanan Informasi #2026! @#$%^&*()_+{}[]:;'<>?,./| \n Baris Baru"
        cipher_hex = encrypt(original, self.key)
        decrypted = decrypt(cipher_hex, self.key)
        self.assertEqual(original, decrypted)

    def test_16_subkeys_generated(self):
        """Memastikan proses Key Scheduling menghasilkan tepat 16 subkey berukuran 48-bit."""
        subkeys = generate_subkeys(normalize_key(self.key))
        self.assertEqual(len(subkeys), 16)
        for subkey in subkeys:
            self.assertEqual(len(subkey), 48)

    def test_pkcs7_padding_behavior(self):
        """Menguji keabsahan padding PKCS#7 manual."""
        # Jika data 5 byte, harus ditambah 3 byte bernilai 0x03 (total 8 byte)
        data = b"12345"
        padded = pkcs7_pad(data, 8)
        self.assertEqual(len(padded), 8)
        self.assertEqual(padded[-1], 3)
        self.assertEqual(pkcs7_unpad(padded), data)

        # Jika data sudah pas 8 byte, PKCS#7 menambahkan 1 blok penuh 8 byte (total 16 byte)
        data_8 = b"12345678"
        padded_8 = pkcs7_pad(data_8, 8)
        self.assertEqual(len(padded_8), 16)
        self.assertEqual(padded_8[-1], 8)
        self.assertEqual(pkcs7_unpad(padded_8), data_8)

    def test_wrong_key_fails(self):
        """Jika kunci salah, dekripsi harus gagal atau menghasilkan karakter acak."""
        msg = "Pesan Rahasia Negara"
        cipher_hex = encrypt(msg, "KunciBenar")
        wrong_decrypted = decrypt(cipher_hex, "KunciSalah")
        self.assertNotEqual(msg, wrong_decrypted)
        print(f"\n[DEMO SALAH KUNCI DES] Pesan Asli: '{msg}' | Hasil jika Kunci Salah: '{wrong_decrypted}'")


if __name__ == '__main__':
    unittest.main()
