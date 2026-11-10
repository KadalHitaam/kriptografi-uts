<?php
/**
 * Sistem Informasi Halaman Admin Terenkripsi
 * Seluruh kode aplikasi berada di berkas ini sesuai PRD.
 */

declare(strict_types=1);

// -----------------------------------------------------------------------------
// BLOK 1: Konfigurasi, koneksi, fungsi kriptografi, dan inisialisasi tabel
// -----------------------------------------------------------------------------

const CONTENT_CIPHER = 'aes-256-cbc';
const RSA_KEY_BITS = 2048;

function escapeHtml(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function findLaragonOpenSslConfig(): string
{
    $candidates = [
        'C:/laragon/bin/php/*/extras/ssl/openssl.cnf',
        'C:/laragon/bin/apache/*/conf/openssl.cnf',
    ];

    foreach ($candidates as $pattern) {
        $matches = glob($pattern);
        if (!is_array($matches)) {
            continue;
        }

        foreach ($matches as $match) {
            if (is_string($match) && is_file($match)) {
                return $match;
            }
        }
    }

    return '';
}

function connectDatabase(): PDO
{
    $host = getenv('DB_HOST') ?: '127.0.0.1';
    $port = getenv('DB_PORT') ?: '3306';
    $database = getenv('DB_NAME') ?: 'db_kriptografi';
    $username = getenv('DB_USER') ?: 'root';
    $password = getenv('DB_PASS') ?: '';

    // Modifikasi: Koneksi ke server MySQL tanpa memilih database terlebih dahulu
    $dsn = sprintf('mysql:host=%s;port=%s;charset=utf8mb4', $host, $port);

    $pdo = new PDO($dsn, $username, $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    // Modifikasi: Buat database otomatis jika belum ada, lalu gunakan database tersebut
    $pdo->exec(sprintf('CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci', $database));
    $pdo->exec(sprintf('USE `%s`', $database));

    return $pdo;
}

function initializeTables(PDO $pdo): void
{
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS encrypted_contents (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(150) NOT NULL,
            ciphertext MEDIUMTEXT NOT NULL,
            iv VARCHAR(64) NOT NULL,
            encrypted_aes_key TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );

    // Private key disimpan sebagai PEM terenkripsi, bukan sebagai berkas terpisah.
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS crypto_key_store (
            id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
            public_key MEDIUMTEXT NOT NULL,
            encrypted_private_key MEDIUMTEXT NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );
}

function loadOrCreateRsaKeys(PDO $pdo, string $masterSecret): array
{
    $query = $pdo->query('SELECT public_key, encrypted_private_key FROM crypto_key_store WHERE id = 1');
    $storedKeys = $query->fetch();

    if ($storedKeys === false) {
        $configPath = findLaragonOpenSslConfig();
        $keyOptions = [
            'private_key_bits' => RSA_KEY_BITS,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        if ($configPath !== '') {
            $keyOptions['config'] = $configPath;
        }

        $keyPair = openssl_pkey_new($keyOptions);

        if ($keyPair === false) {
            throw new RuntimeException('Pasangan kunci RSA gagal dibuat. Pastikan ekstensi OpenSSL aktif dan file openssl.cnf dapat ditemukan.');
        }

        $details = openssl_pkey_get_details($keyPair);
        $privateKeyPem = '';
        $exportOptions = ['encrypt_key_cipher' => 'aes-256-cbc'];
        if ($configPath !== '') {
            $exportOptions['config'] = $configPath;
        }

        $exported = openssl_pkey_export(
            $keyPair,
            $privateKeyPem,
            $masterSecret,
            $exportOptions
        );

        if ($details === false || !isset($details['key']) || !$exported) {
            throw new RuntimeException('Pasangan kunci RSA gagal diekspor.');
        }

        $insert = $pdo->prepare(
            'INSERT IGNORE INTO crypto_key_store (id, public_key, encrypted_private_key)
             VALUES (1, :public_key, :private_key)'
        );
        $insert->execute([
            'public_key' => $details['key'],
            'private_key' => $privateKeyPem,
        ]);

        // Muat ulang agar request bersamaan memakai pasangan kunci yang tersimpan.
        $query = $pdo->query('SELECT public_key, encrypted_private_key FROM crypto_key_store WHERE id = 1');
        $storedKeys = $query->fetch();
    }

    if ($storedKeys === false) {
        throw new RuntimeException('Pasangan kunci RSA tidak dapat dimuat dari database.');
    }

    $privateKey = openssl_pkey_get_private($storedKeys['encrypted_private_key'], $masterSecret);
    if ($privateKey === false) {
        throw new RuntimeException('Private key tidak dapat dibuka. Pastikan APP_MASTER_KEY sama dengan saat inisialisasi.');
    }

    return [
        'public' => $storedKeys['public_key'],
        'private' => $privateKey,
    ];
}

function encryptContent(string $plaintext, string $publicKey): array
{
    $aesKey = random_bytes(32);
    $ivLength = openssl_cipher_iv_length(CONTENT_CIPHER);
    if ($ivLength === false) {
        throw new RuntimeException('Panjang IV untuk algoritma enkripsi tidak dapat ditentukan.');
    }

    $iv = random_bytes($ivLength);
    $ciphertext = openssl_encrypt($plaintext, CONTENT_CIPHER, $aesKey, OPENSSL_RAW_DATA, $iv);
    if ($ciphertext === false) {
        throw new RuntimeException('Konten gagal dienkripsi.');
    }

    $encryptedAesKey = '';
    if (!openssl_public_encrypt($aesKey, $encryptedAesKey, $publicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        throw new RuntimeException('AES key gagal dienkripsi dengan public key RSA.');
    }

    return [
        'ciphertext' => base64_encode($ciphertext),
        'iv' => base64_encode($iv),
        'encrypted_aes_key' => base64_encode($encryptedAesKey),
    ];
}

function decryptContent(array $record, OpenSSLAsymmetricKey $privateKey): string
{
    $ciphertext = base64_decode($record['ciphertext'], true);
    $iv = base64_decode($record['iv'], true);
    $encryptedAesKey = base64_decode($record['encrypted_aes_key'], true);

    if ($ciphertext === false || $iv === false || $encryptedAesKey === false) {
        throw new RuntimeException('Data terenkripsi di database memiliki format yang tidak valid.');
    }

    $aesKey = '';
    if (!openssl_private_decrypt($encryptedAesKey, $aesKey, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        throw new RuntimeException('AES key gagal dipulihkan menggunakan private key RSA.');
    }

    $expectedIvLength = openssl_cipher_iv_length(CONTENT_CIPHER);
    if (strlen($aesKey) !== 32 || $expectedIvLength === false || strlen($iv) !== $expectedIvLength) {
        throw new RuntimeException('Panjang AES key atau IV tidak valid.');
    }

    $plaintext = openssl_decrypt($ciphertext, CONTENT_CIPHER, $aesKey, OPENSSL_RAW_DATA, $iv);
    if ($plaintext === false) {
        throw new RuntimeException('Konten gagal didekripsi.');
    }

    return $plaintext;
}

// -----------------------------------------------------------------------------
// BLOK 2: Request handler POST (enkripsi/simpan) dan GET (ambil/dekripsi)
// -----------------------------------------------------------------------------

$pdo = null;
$items = [];
$selectedRecord = null;
$decryptedContent = null;
$titleInput = '';
$contentInput = '';
$statusMessage = '';
$errorMessage = '';

try {
    $masterSecret = getenv('APP_MASTER_KEY');
    if ($masterSecret === false || trim($masterSecret) === '') {
        $masterSecret = 'v9K#2mP8$zL4wQ1!xR7tY0uN3eJ6fB5a';
    }
    if (strlen($masterSecret) < 32) {
        throw new RuntimeException('Konfigurasikan APP_MASTER_KEY dengan rahasia minimal 32 karakter sebelum menjalankan aplikasi.');
    }

    $pdo = connectDatabase();
    initializeTables($pdo);
    $rsaKeys = loadOrCreateRsaKeys($pdo, $masterSecret);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $titleInput = trim((string) ($_POST['title'] ?? ''));
        $contentInput = trim((string) ($_POST['content'] ?? ''));

        if ($titleInput === '' || $contentInput === '') {
            throw new InvalidArgumentException('Judul dan konten wajib diisi.');
        }
        if (mb_strlen($titleInput) > 150) {
            throw new InvalidArgumentException('Judul maksimal 150 karakter.');
        }

        $encrypted = encryptContent($contentInput, $rsaKeys['public']);
        $insert = $pdo->prepare(
            'INSERT INTO encrypted_contents (title, ciphertext, iv, encrypted_aes_key)
             VALUES (:title, :ciphertext, :iv, :encrypted_aes_key)'
        );
        $insert->execute([
            'title' => $titleInput,
            'ciphertext' => $encrypted['ciphertext'],
            'iv' => $encrypted['iv'],
            'encrypted_aes_key' => $encrypted['encrypted_aes_key'],
        ]);

        header('Location: ?id=' . (int) $pdo->lastInsertId() . '&saved=1');
        exit;
    }

    $listQuery = $pdo->query(
        'SELECT id, title, ciphertext, created_at FROM encrypted_contents ORDER BY created_at DESC, id DESC'
    );
    $items = $listQuery->fetchAll();

    if (isset($_GET['id']) && filter_var($_GET['id'], FILTER_VALIDATE_INT) !== false) {
        $select = $pdo->prepare(
            'SELECT id, title, ciphertext, iv, encrypted_aes_key, created_at
             FROM encrypted_contents WHERE id = :id'
        );
        $select->execute(['id' => (int) $_GET['id']]);
        $selectedRecord = $select->fetch() ?: null;

        if ($selectedRecord !== null) {
            $decryptedContent = decryptContent($selectedRecord, $rsaKeys['private']);
        } else {
            $errorMessage = 'Data yang dipilih tidak ditemukan.';
        }
    }

    if (isset($_GET['saved'])) {
        $statusMessage = 'Konten berhasil dienkripsi dan disimpan ke MySQL.';
    }
} catch (InvalidArgumentException $exception) {
    $errorMessage = $exception->getMessage();
} catch (Throwable $exception) {
    $errorMessage = $exception->getMessage();
}

// Isi kembali daftar saat validasi form gagal setelah koneksi berhasil dibuat.
if ($pdo instanceof PDO && $items === []) {
    try {
        $items = $pdo->query(
            'SELECT id, title, ciphertext, created_at FROM encrypted_contents ORDER BY created_at DESC, id DESC'
        )->fetchAll();
    } catch (Throwable) {
        // Pesan kegagalan utama sudah ditampilkan; jangan menutupi penyebabnya.
    }
}

// -----------------------------------------------------------------------------
// BLOK 3: View HTML dan Tailwind CSS
// -----------------------------------------------------------------------------
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#0b1020">
    <title>Vault Admin — Konten Terenkripsi</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        ink: '#0b1020',
                        panel: '#111a2e',
                        panelSoft: '#17223a',
                        electric: '#38bdf8',
                        violet: '#a78bfa'
                    }
                }
            }
        };
    </script>
</head>
<body class="min-h-screen bg-ink text-slate-100 antialiased">
    <div class="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <header class="mb-8 flex flex-col gap-5 border-b border-slate-800 pb-6 sm:flex-row sm:items-center sm:justify-between">
            <div class="flex items-center gap-4">
                <div class="flex h-12 w-12 items-center justify-center rounded-2xl border border-sky-400/30 bg-sky-400/10 text-electric" aria-hidden="true">
                    <svg class="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                        <rect x="4" y="10" width="16" height="11" rx="2"></rect>
                        <path d="M8 10V7a4 4 0 1 1 8 0v3"></path>
                        <path d="M12 14v3"></path>
                    </svg>
                </div>
                <div>
                    <p class="text-xs font-semibold uppercase tracking-[0.22em] text-electric">Hybrid Cryptography</p>
                    <h1 class="mt-1 text-2xl font-bold tracking-tight text-white sm:text-3xl">Vault Admin</h1>
                </div>
            </div>
            <div class="inline-flex items-center gap-2 self-start rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-sm text-emerald-300 sm:self-auto">
                <span class="h-2 w-2 rounded-full bg-emerald-400"></span>
                AES-256-CBC <span class="text-slate-600">/</span> RSA-2048+
            </div>
        </header>

        <?php if ($statusMessage !== ''): ?>
            <div role="status" class="mb-6 rounded-xl border border-emerald-400/30 bg-emerald-400/10 px-4 py-3 text-sm text-emerald-200">
                <?= escapeHtml($statusMessage) ?>
            </div>
        <?php endif; ?>
        <?php if ($errorMessage !== ''): ?>
            <div role="alert" class="mb-6 rounded-xl border border-rose-400/30 bg-rose-400/10 px-4 py-3 text-sm text-rose-200">
                <?= escapeHtml($errorMessage) ?>
            </div>
        <?php endif; ?>

        <main class="grid gap-6 lg:grid-cols-[340px_minmax(0,1fr)]">
            <aside class="rounded-2xl border border-slate-800 bg-panel p-5 sm:p-6">
                <div class="mb-5 flex items-center justify-between">
                    <div>
                        <h2 class="text-lg font-semibold text-white">Konten tersimpan</h2>
                        <p class="mt-1 text-sm text-slate-400">Data terenkripsi di database</p>
                    </div>
                    <span class="rounded-lg border border-violet-400/20 bg-violet-400/10 px-2.5 py-1 text-xs font-semibold text-violet-300">
                        <?= count($items) ?> item
                    </span>
                </div>

                <?php if ($items === []): ?>
                    <div class="rounded-xl border border-dashed border-slate-700 bg-ink/50 px-4 py-8 text-center">
                        <p class="text-sm font-medium text-slate-300">Belum ada konten</p>
                        <p class="mt-1 text-xs leading-5 text-slate-500">Konten yang disimpan akan muncul di panel ini.</p>
                    </div>
                <?php else: ?>
                    <ul class="space-y-3">
                        <?php foreach ($items as $item): ?>
                            <?php $isSelected = $selectedRecord !== null && (int) $selectedRecord['id'] === (int) $item['id']; ?>
                            <li>
                                <a href="?id=<?= (int) $item['id'] ?>" class="block rounded-xl border px-4 py-3 transition <?= $isSelected ? 'border-sky-400/50 bg-sky-400/10' : 'border-slate-800 bg-ink/40 hover:border-slate-700 hover:bg-panelSoft' ?>">
                                    <div class="flex items-start justify-between gap-3">
                                        <span class="truncate text-sm font-medium text-slate-100"><?= escapeHtml($item['title']) ?></span>
                                        <span class="shrink-0 rounded-md border border-violet-400/20 bg-violet-400/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-violet-300">Encrypted</span>
                                    </div>
                                    <p class="mt-2 truncate font-mono text-[11px] text-slate-500">CT: <?= escapeHtml(substr($item['ciphertext'], 0, 34)) ?>…</p>
                                    <p class="mt-2 text-xs text-slate-500"><?= escapeHtml(date('d M Y, H:i', strtotime($item['created_at']))) ?></p>
                                </a>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </aside>

            <section class="space-y-6">
                <div class="rounded-2xl border border-slate-800 bg-panel p-5 sm:p-7">
                    <div class="mb-6">
                        <p class="text-xs font-semibold uppercase tracking-[0.18em] text-violet-300">Enkripsi konten</p>
                        <h2 class="mt-2 text-xl font-semibold text-white">Simpan konten admin</h2>
                        <p class="mt-1 text-sm text-slate-400">Konten dienkripsi dengan AES; AES key diamankan menggunakan RSA.</p>
                    </div>

                    <form method="post" action="" class="space-y-5">
                        <div>
                            <label for="title" class="mb-2 block text-sm font-medium text-slate-300">Judul konten</label>
                            <input id="title" name="title" type="text" maxlength="150" required value="<?= escapeHtml($titleInput) ?>" placeholder="Contoh: Pengumuman internal" class="w-full rounded-xl border border-slate-700 bg-ink px-4 py-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-electric focus:ring-2 focus:ring-sky-400/15">
                        </div>
                        <div>
                            <label for="content" class="mb-2 block text-sm font-medium text-slate-300">Konten yang akan dienkripsi</label>
                            <textarea id="content" name="content" rows="7" required placeholder="Tulis konten admin di sini…" class="w-full resize-y rounded-xl border border-slate-700 bg-ink px-4 py-3 text-sm leading-6 text-white outline-none placeholder:text-slate-600 focus:border-electric focus:ring-2 focus:ring-sky-400/15"><?= escapeHtml($contentInput) ?></textarea>
                        </div>
                        <div class="flex flex-col gap-3 border-t border-slate-800 pt-5 sm:flex-row sm:items-center sm:justify-between">
                            <p class="text-xs leading-5 text-slate-500">AES-256-CBC untuk konten · RSA-OAEP untuk AES key</p>
                            <button type="submit" class="inline-flex items-center justify-center gap-2 rounded-xl border border-sky-300/20 bg-sky-500 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-300 focus:ring-offset-2 focus:ring-offset-panel">
                                <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12m0 0 4-4m-4 4-4-4"></path><path d="M5 15v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4"></path></svg>
                                Enkripsi &amp; Simpan
                            </button>
                        </div>
                    </form>
                </div>

                <div class="rounded-2xl border border-slate-800 bg-panel p-5 sm:p-7">
                    <div class="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                        <div>
                            <p class="text-xs font-semibold uppercase tracking-[0.18em] text-electric">Pratinjau hasil dekripsi</p>
                            <h2 class="mt-2 text-xl font-semibold text-white">
                                <?= $selectedRecord !== null ? escapeHtml($selectedRecord['title']) : 'Konten plaintext' ?>
                            </h2>
                            <p class="mt-1 text-sm text-slate-400">Plaintext hanya ditampilkan setelah AES key berhasil dipulihkan.</p>
                        </div>
                        <?php if ($selectedRecord !== null): ?>
                            <span class="inline-flex w-fit items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1.5 text-xs font-medium text-emerald-300">
                                <span class="h-1.5 w-1.5 rounded-full bg-emerald-400"></span> Berhasil didekripsi
                            </span>
                        <?php endif; ?>
                    </div>
                    <?php if ($decryptedContent !== null): ?>
                        <div class="min-h-36 whitespace-pre-wrap break-words rounded-xl border border-slate-800 bg-ink p-4 text-sm leading-7 text-slate-200"><?= escapeHtml($decryptedContent) ?></div>
                    <?php else: ?>
                        <div class="flex min-h-36 items-center justify-center rounded-xl border border-dashed border-slate-700 bg-ink/50 p-6 text-center">
                            <p class="max-w-sm text-sm leading-6 text-slate-500">Pilih konten dari daftar di sebelah kiri untuk mengambil ciphertext dari MySQL dan mendekripsinya.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </section>
        </main>

        <footer class="mt-8 border-t border-slate-800 pt-5 text-center text-xs text-slate-600">
            Konten disimpan terenkripsi di MySQL menggunakan kriptografi hibrida.
        </footer>
    </div>
</body>
</html>