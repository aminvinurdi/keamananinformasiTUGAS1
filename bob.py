"""
================================================================================
PROGRAM PIHAK B (BOB) - KOMUNIKASI DUA ARAH TERENKRIPSI
Mata Kuliah: Keamanan Informasi (KI)
================================================================================
Peran:
- Bertindak sebagai Client Connector (menghubungi Alice).
- Memiliki 2 Thread independen:
    1. Thread Receiver (Mendengarkan data ciphertext masuk dari jaringan).
    2. Thread Sender / Main (Membaca input teks user, mengenkripsi, dan mengirim).
- Menggunakan Pre-Shared Key yang sama dengan Alice.
- Kunci TIDAK PERNAH dikirimkan melalui kabel jaringan.
================================================================================
"""

import socket
import threading
import sys
from cipher import encrypt, decrypt

# Kunci Rahasia Default (Pre-Shared Key)
DEFAULT_KEY = "KunciRahasiaKI2026"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000

def receiver_thread(sock, key, stop_event):
    """Thread yang terus mendengarkan ciphertext mentah yang dikirim oleh Alice."""
    while not stop_event.is_set():
        try:
            raw_data = sock.recv(4096)
            if not raw_data:
                print("\n\n[INFO] Koneksi terputus dari pihak Alice.")
                stop_event.set()
                break

            # Data yang lewat di kabel jaringan adalah CIPHERTEXT (Hexadecimal)
            ciphertext_hex = raw_data.decode('utf-8').strip()

            # Dekripsi ciphertext secara manual menggunakan Pre-Shared Key
            plaintext = decrypt(ciphertext_hex, key)

            print("\n" + "="*60)
            print("<<< [DATA MASUK DARI JARINGAN TCP]")
            print(f"    [Ciphertext Mentah] : {ciphertext_hex}")
            print(f"    [Status Kunci]      : Menggunakan Pre-Shared Key lokal")
            print(f"    [Hasil Dekripsi]    : \033[92m{plaintext}\033[0m")
            print("="*60)
            print("[Bob > ] ", end="", flush=True)

        except (ConnectionResetError, ConnectionAbortedError):
            print("\n[INFO] Alice telah menutup koneksi.")
            stop_event.set()
            break
        except Exception as e:
            if not stop_event.is_set():
                print(f"\n[ERROR RECEIVER]: {e}")
            break


def main():
    print("="*60)
    print("      SIMULASI KOMUNIKASI DUA ARAH TERENKRIPSI (KI)      ")
    print("                      PIHAK B (BOB)                      ")
    print("="*60)

    # Konfigurasi Koneksi & Key
    host = input(f"Masukkan IP Address Alice [Tekan Enter untuk '{DEFAULT_HOST}']: ").strip()
    host = host if host else DEFAULT_HOST

    port_str = input(f"Masukkan Port Alice [Tekan Enter untuk {DEFAULT_PORT}]: ").strip()
    port = int(port_str) if port_str else DEFAULT_PORT

    input_key = input(f"Masukkan Pre-Shared Key [Tekan Enter untuk default '{DEFAULT_KEY}']: ").strip()
    key = input_key if input_key else DEFAULT_KEY

    print("\n[KONFIGURASI KEAMANAN]")
    print(f"[*] Target Host    : {host}:{port}")
    print(f"[*] Pre-Shared Key : '{key}' (Tersimpan aman di memori lokal)")
    print(f"[*] Catatan        : Key TIDAK AKAN PERNAH dikirim ke jaringan.")
    print("="*60)

    # Inisialisasi Socket Client (Bob)
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        print(f"[*] Menghubungi Alice di {host}:{port}...")
        client_sock.connect((host, port))
        print(f"[+] BERHASIL TERHUBUNG ke Alice!")
        print("[+] Saluran transmisi dua arah aktif! Ketik pesan lalu tekan Enter.")
        print("[+] Ketik 'exit' atau 'keluar' untuk mengakhiri sesi.\n")
    except Exception as e:
        print(f"[!] Gagal terhubung ke Alice: {e}")
        print("[!] Pastikan 'python alice.py' sudah dijalankan terlebih dahulu di terminal lain.")
        return

    stop_event = threading.Event()

    # Jalankan thread penerima pesan
    recv_t = threading.Thread(target=receiver_thread, args=(client_sock, key, stop_event), daemon=True)
    recv_t.start()

    # Loop utama pengirim pesan (Bob)
    try:
        while not stop_event.is_set():
            try:
                msg = input("[Bob > ] ")
            except EOFError:
                break

            if not msg.strip():
                continue

            if msg.strip().lower() in ['exit', 'keluar']:
                print("\n[INFO] Mengakhiri percakapan...")
                stop_event.set()
                break

            # 1. Enkripsi teks asli secara manual dengan RC4
            ciphertext_hex = encrypt(msg, key)

            print("-"*60)
            print(">>> [TRANSMISI DATA KE JARINGAN TCP]")
            print(f"    [Plaintext Asli]    : {msg}")
            print(f"    [Ciphertext Terikrim] : \033[93m{ciphertext_hex}\033[0m")
            print(f"    [Panjang Ciphertext]  : {len(ciphertext_hex)} karakter hex")
            print("-"*60)

            # 2. Kirim HANYA CIPHERTEXT ke kabel jaringan
            try:
                client_sock.sendall(ciphertext_hex.encode('utf-8'))
            except Exception as e:
                print(f"[!] Gagal mengirim data: {e}")
                break

    except KeyboardInterrupt:
        print("\n[INFO] Sesi dihentikan oleh pengguna.")
    finally:
        stop_event.set()
        client_sock.close()
        print("[*] Socket ditutup. Program Bob selesai.")


if __name__ == "__main__":
    main()
