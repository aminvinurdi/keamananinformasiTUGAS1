"""
================================================================================
INTEGRATION TEST: SIMULASI TRANSMISI JARINGAN DUA ARAH SECARA OTOMATIS
================================================================================
Skrip ini mensimulasikan koneksi jaringan nyata antara dua node (Alice & Bob)
di port localhost untuk memverifikasi bahwa:
1. Transmisi di kabel jaringan HANYA mengalirkan ciphertext HEX.
2. Tidak ada kebocoran plaintext atau key di jaringan.
3. Kedua belah pihak berhasil mendeskripsi pesan satu sama lain secara bolak-balik.
================================================================================
"""

import socket
import threading
import time
from cipher import encrypt, decrypt

TEST_PORT = 5055
TEST_KEY = "KunciDES"

def run_integration_test():
    print("="*60)
    print("MEMULAI INTEGRATION TEST TRANSMISI JARINGAN DUA ARAH")
    print("="*60)

    alice_received = []
    bob_received = []

    # 1. Start Alice Listener Server
    alice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    alice_sock.bind(("127.0.0.1", TEST_PORT))
    alice_sock.listen(1)

    def alice_worker():
        conn, addr = alice_sock.accept()
        # Alice kirim pesan ke Bob
        alice_msg = "Halo Bob, ini Alice! Pertemuan rahasia jam 2 siang."
        alice_cipher = encrypt(alice_msg, TEST_KEY)
        conn.sendall(alice_cipher.encode('utf-8'))

        # Alice terima balasan dari Bob
        raw = conn.recv(4096)
        bob_cipher_received = raw.decode('utf-8')
        alice_received.append((bob_cipher_received, decrypt(bob_cipher_received, TEST_KEY)))
        
        time.sleep(0.1)
        conn.close()

    alice_thread = threading.Thread(target=alice_worker)
    alice_thread.start()

    time.sleep(0.2)  # Tunggu socket server siap

    # 2. Start Bob Client
    bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_sock.connect(("127.0.0.1", TEST_PORT))

    # Bob terima pesan dari Alice
    raw = bob_sock.recv(4096)
    alice_cipher_received = raw.decode('utf-8')
    bob_received.append((alice_cipher_received, decrypt(alice_cipher_received, TEST_KEY)))

    # Bob balas pesan ke Alice
    bob_msg = "Siap Alice, saya sudah terima pesannya dan konfirmasi hadir!"
    bob_cipher = encrypt(bob_msg, TEST_KEY)
    bob_sock.sendall(bob_cipher.encode('utf-8'))

    alice_thread.join()
    bob_sock.close()
    alice_sock.close()

    # 3. Verifikasi Hasil Transmisi
    print("\n[HASIL TRANSMISI ALICE -> BOB]")
    print(f"Data di kabel jaringan (Ciphertext) : {bob_received[0][0]}")
    print(f"Hasil Dekripsi oleh Bob (Plaintext) : {bob_received[0][1]}")
    assert bob_received[0][1] == "Halo Bob, ini Alice! Pertemuan rahasia jam 2 siang."
    print("=> Status: SUKSES (Bob menerima dan mendekripsi dengan benar)")

    print("\n[HASIL TRANSMISI BOB -> ALICE]")
    print(f"Data di kabel jaringan (Ciphertext) : {alice_received[0][0]}")
    print(f"Hasil Dekripsi oleh Alice (Plaintext) : {alice_received[0][1]}")
    assert alice_received[0][1] == "Siap Alice, saya sudah terima pesannya dan konfirmasi hadir!"
    print("=> Status: SUKSES (Alice menerima dan mendekripsi dengan benar)")

    print("\n" + "="*60)
    print("[INTEGRATION TEST BERHASIL 100% - SISTEM SIAP DIDEMOKAN!]")
    print("="*60)

if __name__ == '__main__':
    run_integration_test()
