"""
================================================================================
PROGRAM PIHAK A (ALICE) - KOMUNIKASI DUA ARAH TERENKRIPSI (DES MANUAL)
Mata Kuliah: Keamanan Informasi (KI)
================================================================================
Peran:
- Bertindak sebagai Server Listener (menunggu koneksi dari Bob).
- Menggunakan Algoritma DES (Data Encryption Standard) 16-Round Manual.
- Memiliki 2 Thread independen (Receiver & Sender).
- Menggunakan Pre-Shared Key (Kunci tidak pernah dikirimkan melalui jaringan).
================================================================================
"""

import socket
import threading
import sys
from cipher import encrypt, decrypt

# Kunci Rahasia Default DES (Pre-Shared Key 8 Karakter / 64-bit)
DEFAULT_KEY = "KunciDES"
DEFAULT_PORT = 5000

def receiver_thread(conn, key, stop_event):
    """Thread yang terus mendengarkan ciphertext mentah yang dikirim oleh Bob."""
    while not stop_event.is_set():
        try:
            # Menerima data dari socket jaringan
            raw_data = conn.recv(4096)
            if not raw_data:
                print("\n\n[INFO] Koneksi terputus dari pihak Bob.")
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
            print("[Alice >] ", end="", flush=True)

        except (ConnectionResetError, ConnectionAbortedError):
            print("\n[INFO] Bob telah menutup koneksi.")
            stop_event.set()
            break
        except Exception as e:
            if not stop_event.is_set():
                print(f"\n[ERROR RECEIVER]: {e}")
            break


def main():
    print("="*60)
    print("      SIMULASI KOMUNIKASI DUA ARAH TERENKRIPSI (KI)      ")
    print("                     PIHAK A (ALICE)                     ")
    print("="*60)
    
    # Konfigurasi Key & Port
    input_key = input(f"Masukkan Pre-Shared Key [Tekan Enter untuk default '{DEFAULT_KEY}']: ").strip()
    key = input_key if input_key else DEFAULT_KEY

    port_str = input(f"Masukkan Port Listener [Tekan Enter untuk default {DEFAULT_PORT}]: ").strip()
    port = int(port_str) if port_str else DEFAULT_PORT

    print("\n[KONFIGURASI KEAMANAN]")
    print(f"[*] Pre-Shared Key : '{key}' (Tersimpan aman di memori lokal)")
    print(f"[*] Catatan        : Key TIDAK AKAN PERNAH dikirim ke jaringan.")
    print("="*60)

    # Inisialisasi Socket Server (Alice)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # SO_REUSEADDR agar port bisa langsung dipakai ulang tanpa menunggu TIME_WAIT
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind(("0.0.0.0", port))
        server_sock.listen(1)
        print(f"[*] Menunggu koneksi dari Bob di port {port}...")
        print("[*] (Buka terminal kedua dan jalankan 'python bob.py')\n")
        
        conn, addr = server_sock.accept()
        print(f"[+] TERHUBUNG dengan Bob di alamat IP: {addr[0]}:{addr[1]}")
        print("[+] Saluran transmisi dua arah aktif! Ketik pesan lalu tekan Enter.")
        print("[+] Ketik 'exit' atau 'keluar' untuk mengakhiri sesi.\n")
    except Exception as e:
        print(f"[!] Gagal memulai listener socket: {e}")
        return

    stop_event = threading.Event()

    # Jalankan thread penerima pesan
    recv_t = threading.Thread(target=receiver_thread, args=(conn, key, stop_event), daemon=True)
    recv_t.start()

    # Loop utama pengirim pesan (Alice)
    try:
        while not stop_event.is_set():
            try:
                msg = input("[Alice > ] ")
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
                conn.sendall(ciphertext_hex.encode('utf-8'))
            except Exception as e:
                print(f"[!] Gagal mengirim data: {e}")
                break

    except KeyboardInterrupt:
        print("\n[INFO] Sesi dihentikan oleh pengguna.")
    finally:
        stop_event.set()
        conn.close()
        server_sock.close()
        print("[*] Socket ditutup. Program Alice selesai.")


if __name__ == "__main__":
    main()
