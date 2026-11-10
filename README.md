# Vault Admin

Aplikasi admin untuk menyimpan konten teks dalam bentuk terenkripsi di database MySQL dengan pendekatan hybrid cryptography. Aplikasi ini dibuat dalam satu berkas utama, yaitu [index.php](index.php), dan tetap menjaga tampilan UI Tailwind yang sudah ada.

## Deskripsi

Aplikasi ini memungkinkan admin untuk:

- menulis judul dan konten plaintext,
- mengenkripsi konten menggunakan AES-256-CBC,
- mengenkripsi kunci AES menggunakan RSA-2048 dengan padding OAEP,
- menyimpan hasil enkripsi ke database MySQL,
- menampilkan daftar konten yang tersimpan,
- memilih record tertentu dan mendekripsi konten kembali ke plaintext.

## Fitur utama

- Enkripsi konten dengan AES-256-CBC
- Enkripsi kunci AES dengan RSA-2048
- Penyimpanan ciphertext, IV, dan kunci terenkripsi di MySQL
- Pembuatan database otomatis jika belum ada
- Pembuatan pasangan kunci RSA otomatis saat pertama kali dijalankan
- Deteksi otomatis konfigurasi OpenSSL pada Laragon
- Fallback master key agar aplikasi tetap berjalan jika variabel lingkungan tidak di-set
- UI admin satu halaman dengan layout Tailwind CSS

## Teknologi yang digunakan

- PHP
- PDO MySQL
- OpenSSL
- MySQL / MariaDB
- Tailwind CSS via CDN

## Struktur aplikasi

- [index.php](index.php) seluruh logika aplikasi, koneksi database, enkripsi/dekripsi, serta view UI

## Prasyarat

- Laragon terinstal di Windows
- Apache + MySQL aktif
- PHP yang tersedia di Laragon
- Ekstensi OpenSSL aktif di PHP

## Cara menjalankan di Laragon

1. Clone atau copy project ke folder web Laragon, misalnya:

   ```text
   C:/laragon/www/kriptografi-uts
   ```

2. Jalankan Apache dan MySQL dari Laragon.

3. Akses project lewat browser, misalnya:

   ```text
   http://localhost/kriptografi-uts/
   ```

4. Jika aplikasi belum memiliki database `db_kriptografi`, aplikasi akan membuatnya secara otomatis.

## Konfigurasi variabel lingkungan

Aplikasi membaca variabel lingkungan berikut jika tersedia:

- `DB_HOST`
- `DB_PORT`
- `DB_NAME`
- `DB_USER`
- `DB_PASS`
- `APP_MASTER_KEY`

Jika variabel tidak di-set, aplikasi akan menggunakan nilai default berikut:

- Host: `127.0.0.1`
- Port: `3306`
- Database: `db_kriptografi`
- User: `root`
- Password: kosong
- `APP_MASTER_KEY`: nilai bawaan 32 karakter yang sudah ditentukan dalam aplikasi

> Catatan: Disarankan untuk mengatur `APP_MASTER_KEY` secara aman dan minimal 32 karakter agar kunci private RSA dapat dipulihkan dengan konsisten.

## Database

Saat aplikasi dijalankan, sistem akan:

1. melakukan koneksi ke server MySQL tanpa memilih database,
2. membuat database `db_kriptografi` jika belum ada,
3. menggunakan database tersebut,
4. membuat tabel berikut jika belum ada:
   - `encrypted_contents`
   - `crypto_key_store`

## Flow kerja aplikasi

1. Admin memasukkan judul dan konten.
2. Konten dienkripsi dengan AES-256-CBC.
3. Kunci AES dienkripsi dengan public key RSA.
4. Data hasil enkripsi disimpan ke MySQL.
5. Saat item dipilih, ciphertext dan kunci terenkripsi dibaca ulang.
6. Private key RSA dibuka dengan `APP_MASTER_KEY`.
7. Kunci AES dipulihkan lalu ciphertext didekripsi menjadi plaintext.

## Keamanan

- Private key RSA disimpan dalam bentuk terenkripsi, bukan dalam file terpisah.
- Kunci master digunakan untuk membuka private key saat runtime.
- Aplikasi menghindari penyimpanan plaintext di database.

## Catatan

Aplikasi ini dirancang untuk berjalan plug-and-play pada Laragon tanpa perlu memisahkan logika ke file baru. UI dan layout tetap dipertahankan seperti yang sudah dibuat.
