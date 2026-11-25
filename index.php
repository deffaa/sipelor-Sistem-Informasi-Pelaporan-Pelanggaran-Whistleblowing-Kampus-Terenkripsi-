<?php
declare(strict_types=1);
session_start();

require_once __DIR__ . '/config/db.php';
require_once __DIR__ . '/config/crypto.php';

if (!empty($_SESSION['admin_authenticated'])) {
    header('Location: admin.php');
    exit;
}

$generatedKeys = null;
$systemError = null;
$loginError = null;
$systemReady = isSystemInitialized();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // 1. One-click Key Generation on Landing Page
    if ($action === 'generate_keys') {
        try {
            $generatedKeys = generateSystemKeys();
            $systemReady = true;
        } catch (Throwable $e) {
            $systemError = $e->getMessage();
        }
    }

    // 2. Paradigm-Shifted Admin Login (Symmetric + Asymmetric Keys)
    if ($action === 'admin_login') {
        $symmetricKey = trim($_POST['symmetric_key'] ?? '');
        $privateKey = trim($_POST['private_key'] ?? '');

        if (!$systemReady) {
            $loginError = 'Kunci kriptografi belum dibuat. Klik tombol "Generate Kunci Simetris & Asimetris" terlebih dahulu.';
        } elseif ($symmetricKey === '' || $privateKey === '') {
            $loginError = 'Kunci Simetris dan Kunci Asimetris (RSA Private Key) wajib diisi.';
        } else {
            $isKeyValid = verifyDualKeyLogin($symmetricKey, $privateKey);

            session_regenerate_id(true);
            $_SESSION['admin_authenticated'] = true;
            $_SESSION['key_verified'] = $isKeyValid;
            $_SESSION['admin_symmetric_key'] = $symmetricKey;
            $_SESSION['admin_private_key'] = $privateKey;
            $_SESSION['login_time'] = date('H:i:s');

            header('Location: admin.php');
            exit;
        }
    }
}

$totalRecords = (int) $pdo->query('SELECT COUNT(*) FROM encrypted_reports')->fetchColumn();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIPELOR — Gerbang Autentikasi Admin Terenkripsi</title>
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
            <div class="status-pill">
                <span class="status-dot <?= $systemReady ? 'is-active' : 'is-warn' ?>"></span>
                <span><?= $systemReady ? "AES-256 + RSA-2048 Aktif • {$totalRecords} Laporan" : 'Kunci Belum Dibuat' ?></span>
            </div>
        </div>
    </header>

    <main class="container landing-layout">
        <!-- Left Column: SIPELOR Overview & 1-Click Key Provisioning -->
        <section class="landing-info">
            <span class="eyebrow">Sistem Informasi Pelaporan Terenkripsi</span>
            <h1 class="hero-title">Gerbang Masuk Admin Berbasis Kunci Kriptografi</h1>
            <p class="hero-subtitle">
                SIPELOR mengamankan seluruh laporan pelanggaran akademik secara eksklusif di ruang admin. Akses masuk tidak menggunakan username dan password, melainkan kombinasi <strong>Kunci Simetris (AES-256)</strong> dan <strong>Kunci Asimetris (RSA-2048 Private Key)</strong>.
            </p>

            <div class="card key-setup-card">
                <div class="card-head-compact">
                    <h2 class="section-title">Pembangkit Kunci Kriptografi</h2>
                    <p class="body-muted">
                        Bangkitkan pasangan kunci baru dalam satu klik. Server hanya menyimpan <code>public.pem</code> dan <em>hash</em> kunci simetris.
                    </p>
                </div>

                <?php if ($systemError): ?>
                    <div class="alert alert-error" role="alert"><?= htmlspecialchars($systemError) ?></div>
                <?php endif; ?>

                <form method="POST">
                    <input type="hidden" name="action" value="generate_keys">
                    <button type="submit" class="btn btn-secondary">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
                        </svg>
                        <span><?= $systemReady ? 'Generate Ulang Pasangan Kunci' : 'Generate Kunci Simetris & Asimetris' ?></span>
                    </button>
                </form>

                <?php if ($generatedKeys): ?>
                    <div class="generated-box">
                        <div class="alert alert-success" role="status">
                            Kunci berhasil dibuat. Simpan kedua kunci ini atau klik tombol isi otomatis ke form login.
                        </div>

                        <div class="form-group">
                            <div class="key-header">
                                <label for="gen-sym" class="form-label">Kunci Simetris (AES-256 Hex)</label>
                                <button type="button" class="btn btn-ghost btn-sm" data-copy-target="gen-sym">Salin</button>
                            </div>
                            <input id="gen-sym" type="text" class="form-control mono-text" readonly value="<?= htmlspecialchars($generatedKeys['symmetric_key']) ?>">
                        </div>

                        <div class="form-group">
                            <div class="key-header">
                                <label for="gen-priv" class="form-label">Kunci Asimetris (RSA-2048 Private Key)</label>
                                <button type="button" class="btn btn-ghost btn-sm" data-copy-target="gen-priv">Salin</button>
                            </div>
                            <textarea id="gen-priv" class="form-control mono-text" rows="5" readonly><?= htmlspecialchars($generatedKeys['private_key']) ?></textarea>
                        </div>

                        <button type="button" id="btn-autofill-keys" class="btn btn-ghost btn-sm">
                            Isi Otomatis ke Form Login Admin &rarr;
                        </button>
                    </div>
                <?php endif; ?>
            </div>
        </section>

        <!-- Right Column: Dual-Key Admin Login Gate -->
        <section class="card card-accent-border" aria-labelledby="login-heading">
            <div class="card-head">
                <span class="eyebrow">Autentikasi Paradigma Baru</span>
                <h2 id="login-heading" class="section-title">Login Halaman Admin</h2>
                <p class="body-muted">
                    Masukkan <strong>Kunci Simetris</strong> dan <strong>Kunci Asimetris (RSA Private Key)</strong>. Jika Private Key salah, halaman admin akan terkunci dalam tampilan ciphertext.
                </p>
            </div>

            <?php if ($loginError): ?>
                <div class="alert alert-error" role="alert"><?= htmlspecialchars($loginError) ?></div>
            <?php endif; ?>

            <form method="POST" class="stack-form">
                <input type="hidden" name="action" value="admin_login">

                <div class="form-group">
                    <label for="symmetric_key" class="form-label">1. Kunci Simetris (AES-256 Key)</label>
                    <input type="password" id="symmetric_key" name="symmetric_key" class="form-control mono-text" placeholder="Tempel 64-karakter hex kunci simetris..." required>
                    <button type="button" class="toggle-secret-btn" data-toggle-input="symmetric_key">Tampilkan / Sembunyikan Kunci</button>
                </div>

                <div class="form-group">
                    <label for="private_key" class="form-label">2. Kunci Asimetris (RSA Private Key)</label>
                    <textarea id="private_key" name="private_key" class="form-control mono-text" rows="8" placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----" required></textarea>
                </div>

                <button type="submit" class="btn btn-primary btn-full">Verifikasi Kunci &amp; Masuk Admin</button>
            </form>
        </section>
    </main>

    <footer class="site-footer">
        <div class="container footer-inner">
            <span>SIPELOR — Sistem Informasi Pelaporan Terenkripsi</span>
            <span>Arsitektur: PHP Native + OpenSSL Hybrid Cryptography</span>
        </div>
    </footer>

    <script src="assets/js/app.js"></script>
</body>
</html>