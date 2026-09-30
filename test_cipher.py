"""
================================================================================
UNIT TEST OTOMATIS: VALIDASI ALGORITMA KRIPTOGRAFI MANUAL (cipher.py)
================================================================================
File ini bertugas menguji ketahanan, kesesuaian, dan sifat kriptografi dari
implementasi RC4 manual kita.
================================================================================
"""

import unittest
from cipher import encrypt, decrypt, ksa, prga

class TestManualRC4(unittest.TestCase):

    def setUp(self):
        self.key = "KunciRahasiaKI2026"

    def test_basic_encryption_decryption(self):
        """Memastikan pesan biasa berhasil dienkripsi dan didekripsi kembali utuh."""
        original = "Halo Bob, selamat siang!"
        cipher_hex = encrypt(original, self.key)
        self.assertNotEqual(original, cipher_hex)
        decrypted = decrypt(cipher_hex, self.key)
        self.assertEqual(original, decrypted)

    def test_special_characters_and_numbers(self):
        """Memastikan karakter khusus, angka, dan baris baru tidak merusak cipher."""
        original = "Pesan Rahasia #1234! @#$%^&*()_+{}[]:;'<>?,./| \n Baris Baru"
        cipher_hex = encrypt(original, self.key)
        decrypted = decrypt(cipher_hex, self.key)
        self.assertEqual(original, decrypted)

    def test_different_keys_produce_different_ciphertext(self):
        """Dua kunci berbeda harus menghasilkan ciphertext berbeda untuk pesan yang sama."""
        msg = "Informasi Rahasia Negara"
        c1 = encrypt(msg, "KunciA")
        c2 = encrypt(msg, "KunciB")
        self.assertNotEqual(c1, c2)

    def test_wrong_key_fails_to_decrypt(self):
        """Jika penerima menggunakan kunci yang salah, plaintext tidak boleh terbaca."""
        msg = "Pesan Sangat Rahasia"
        cipher_hex = encrypt(msg, "KunciBenar")
        wrong_decrypted = decrypt(cipher_hex, "KunciSalah")
        self.assertNotEqual(msg, wrong_decrypted)
        print(f"\n[DEMO SALAH KUNCI] Pesan Asli: '{msg}' | Hasil jika Kunci Salah: '{wrong_decrypted}'")

    def test_ksa_permutation(self):
        """Memastikan array S berukuran tepat 256 dan berisi permutasi valid angka 0-255."""
        S = ksa(self.key.encode('utf-8'))
        self.assertEqual(len(S), 256)
        self.assertEqual(sorted(S), list(range(256)))


if __name__ == '__main__':
    unittest.main()
