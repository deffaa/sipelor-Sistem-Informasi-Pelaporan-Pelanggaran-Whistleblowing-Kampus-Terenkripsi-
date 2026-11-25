<?php
declare(strict_types=1);
require_once __DIR__ . '/config/crypto.php';

$generatedSymmetricKey = null;
$generatedPrivateKey = null;
$generatedPublicKey = null;
$errorMsg = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!is_dir(KEYS_DIR)) {
        mkdir(KEYS_DIR, 0755, true);
    }

    $config = getOpenSslConfig();
    $res = openssl_pkey_new($config);

    if ($res === false) {
        $errorMsg = 'OpenSSL gagal membangkitkan pasangan kunci RSA. Pastikan ekstensi openssl aktif di php.ini.';
    } else {
        openssl_pkey_export($res, $privateKeyPem, null, $config);
        $details = openssl_pkey_get_details($res);
        $publicKeyPem = $details['key'];

        // Generate 256-bit Symmetric Key (64 hex characters)
        $symmetricKey = bin2hex(random_bytes(32));

        // Save only Public Key & Symmetric Hash on server (Private Key is held by Admin)
        file_put_contents(PUBLIC_KEY_PATH, $publicKeyPem);
        file_put_contents(SYMMETRIC_HASH_PATH, hash('sha256', $symmetricKey));

        $generatedSymmetricKey = $symmetricKey;
        $generatedPrivateKey = $privateKeyPem;
        $generatedPublicKey = $publicKeyPem;
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Key Provisioning — SIPELOR</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <header class="site-header">
        <div class="container header-inner">
            <a href="index.php" class="brand">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                <span>SIPELOR</span>
            </a>
            <nav class="nav-links" aria-label="Main Navigation">
                <a href="index.php" class="nav-link">Kembali ke Landing Page</a>
            </nav>
        </div>
    </header>

    <main class="container section-block">
        <div class="card card-narrow">
            <span class="eyebrow">Inisialisasi Kriptografi</span>
            <h1 class="page-title">Generator Kunci Simetris &amp; Asimetris</h1>
            <p class="body-muted">
                Bangkitkan pasangan kunci <strong>RSA-2048 (Asimetris)</strong> dan <strong>AES-256 Master Key (Simetris)</strong>. Server hanya menyimpan <code>public.pem</code> dan <em>hash</em> kunci simetris. Simpan kredensial di bawah ini untuk login ke halaman admin.
            </p>

            <?php if ($errorMsg): ?>
                <div class="alert alert-error" role="alert"><?= htmlspecialchars($errorMsg) ?></div>
            <?php endif; ?>

            <form method="POST" class="stack-form">
                <button type="submit" class="btn btn-primary">
                    <?= isSystemInitialized() ? 'Regenerasi Pasangan Kunci Baru' : 'Generate Kunci Simetris & Asimetris' ?>
                </button>
            </form>

            <?php if ($generatedSymmetricKey && $generatedPrivateKey): ?>
                <div class="alert alert-success" role="status">
                    Kunci berhasil dibuat. Salin dan simpan kedua kunci berikut untuk masuk ke dashboard admin.
                </div>

                <div class="key-output-group">
                    <div class="key-header">
                        <label for="out-sym" class="form-label">1. Kunci Simetris Admin (AES-256 Hex Key)</label>
                        <button type="button" class="btn btn-ghost btn-sm" data-copy-target="out-sym">Salin Kunci</button>
                    </div>
                    <input id="out-sym" type="text" class="form-control mono-text" readonly value="<?= htmlspecialchars($generatedSymmetricKey) ?>">
                </div>

                <div class="key-output-group">
                    <div class="key-header">
                        <label for="out-priv" class="form-label">2. Kunci Asimetris Admin (RSA-2048 Private Key)</label>
                        <button type="button" class="btn btn-ghost btn-sm" data-copy-target="out-priv">Salin Private Key</button>
                    </div>
                    <textarea id="out-priv" class="form-control mono-text" rows="10" readonly><?= htmlspecialchars($generatedPrivateKey) ?></textarea>
                </div>

                <div class="action-footer">
                    <a href="index.php#admin-login" class="btn btn-primary">Lanjut ke Landing Page &amp; Login Admin</a>
                </div>
            <?php endif; ?>
        </div>
    </main>
    <script src="assets/js/app.js"></script>
</body>
</html>