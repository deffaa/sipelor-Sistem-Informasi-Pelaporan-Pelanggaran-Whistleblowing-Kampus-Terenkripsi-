<?php
declare(strict_types=1);
session_start();

require_once __DIR__ . '/config/db.php';
require_once __DIR__ . '/config/crypto.php';

if (empty($_SESSION['admin_authenticated'])) {
    header('Location: index.php');
    exit;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$isVerified = !empty($_SESSION['key_verified']);
$cipherOnlyMode = isset($_GET['view']) && $_GET['view'] === 'cipher';

// Handle Admin Actions (Only permitted when cryptographic keys are verified)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $isVerified) {
    $action = $_POST['action'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';

    if (!hash_equals($_SESSION['csrf_token'], $csrfToken)) {
        $_SESSION['flash_alert'] = ['type' => 'error', 'text' => 'Token keamanan sesi tidak valid.'];
        header('Location: admin.php');
        exit;
    }

    // 1. Admin Saves New Encrypted Report (with Encrypted ID & Encrypted Report Code)
    if ($action === 'save_report') {
        $alias = trim($_POST['reporter_alias'] ?? '');
        $category = trim($_POST['category'] ?? '');
        $subject = trim($_POST['subject'] ?? '');
        $chronology = trim($_POST['chronology'] ?? '');

        if ($category === '' || $subject === '' || $chronology === '') {
            $_SESSION['flash_alert'] = ['type' => 'error', 'text' => 'Kategori, subjek laporan, dan kronologi wajib diisi.'];
        } else {
            try {
                $plainId = 'ID-' . strtoupper(bin2hex(random_bytes(4)));
                $plainReportCode = 'RPT-' . strtoupper(bin2hex(random_bytes(4)));

                $payload = [
                    'plain_id'       => $plainId,
                    'report_code'    => $plainReportCode,
                    'reporter_alias' => $alias !== '' ? $alias : 'Anonim / Rahasia',
                    'category'       => $category,
                    'subject'        => $subject,
                    'chronology'     => $chronology,
                    'submitted_at'   => date('Y-m-d H:i:s'),
                ];

                $encrypted = hybridEncryptPayload($payload, $plainId, $plainReportCode);

                $stmt = $pdo->prepare(
                    'INSERT INTO encrypted_reports (id, report_code, ciphertext, encrypted_aes_key, iv_base64)
                     VALUES (:id, :code, :cipher, :aes_key, :iv)'
                );
                $stmt->execute([
                    ':id'      => $encrypted['encrypted_id'],
                    ':code'    => $encrypted['encrypted_code'],
                    ':cipher'  => $encrypted['ciphertext'],
                    ':aes_key' => $encrypted['encrypted_aes_key'],
                    ':iv'      => $encrypted['iv_base64'],
                ]);

                $_SESSION['flash_alert'] = [
                    'type' => 'success',
                    'text' => "Laporan rahasia ({$plainReportCode} / {$plainId}) berhasil dienkripsi penuh termasuk ID database-nya.",
                ];
            } catch (Throwable $e) {
                $_SESSION['flash_alert'] = ['type' => 'error', 'text' => 'Gagal mengenkripsi laporan: ' . $e->getMessage()];
            }
        }

        header('Location: admin.php');
        exit;
    }

    // 2. Delete Single Report using Encrypted String Primary Key
    if ($action === 'delete_single') {
        $encryptedId = trim($_POST['report_id'] ?? '');
        if ($encryptedId !== '') {
            $stmt = $pdo->prepare('DELETE FROM encrypted_reports WHERE id = :id');
            $stmt->execute([':id' => $encryptedId]);
            $_SESSION['flash_alert'] = ['type' => 'success', 'text' => 'Rekaman laporan terenkripsi berhasil dihapus dari database.'];
        }
        header('Location: admin.php');
        exit;
    }

    // 3. Delete All Reports
    if ($action === 'delete_all') {
        $deletedCount = (int) $pdo->exec('DELETE FROM encrypted_reports');
        $_SESSION['flash_alert'] = ['type' => 'success', 'text' => "Seluruh {$deletedCount} rekaman terenkripsi berhasil dibersihkan."];
        header('Location: admin.php');
        exit;
    }
}

$flashAlert = $_SESSION['flash_alert'] ?? null;
unset($_SESSION['flash_alert']);

$privateKeyPem = (string) ($_SESSION['admin_private_key'] ?? '');
$symmetricKey = (string) ($_SESSION['admin_symmetric_key'] ?? '');
$keyFingerprint = strtoupper(substr(hash('sha256', $symmetricKey), 0, 12));

$records = $pdo->query('SELECT * FROM encrypted_reports ORDER BY created_at DESC')->fetchAll();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= renderUiText('Admin Vault — SIPELOR Terenkripsi', $isVerified) ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="<?= $isVerified ? '' : 'is-cipher-locked' ?>">
    <header class="site-header">
        <div class="container header-inner">
            <a href="admin.php" class="brand">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
                <span><?= renderUiText('SIPELOR ADMIN', $isVerified) ?></span>
            </a>
            <nav class="nav-links" aria-label="Navigasi Admin">
                <span class="session-badge mono-text"><?= renderUiText("KEY-ID: {$keyFingerprint}", $isVerified) ?></span>
                <a href="logout.php" class="btn btn-secondary btn-sm" title="Akhiri Sesi Kunci">
                    <?= renderUiText('Akhiri Sesi Kunci', $isVerified) ?>
                </a>
            </nav>
        </div>
    </header>

    <main class="container section-block">
        <?php if ($flashAlert && $isVerified): ?>
            <div class="alert <?= $flashAlert['type'] === 'success' ? 'alert-success' : 'alert-error' ?>" role="status">
                <?= htmlspecialchars($flashAlert['text']) ?>
            </div>
        <?php endif; ?>

        <!-- Section 1: Admin-Only Confidential Report Input -->
        <?php if ($isVerified): ?>
            <section class="card form-section" aria-labelledby="input-report-heading">
                <div class="card-head">
                    <span class="eyebrow">01 / Input Data Rahasia (Khusus Admin)</span>
                    <h1 id="input-report-heading" class="page-title">Simpan Laporan Pelanggaran Baru</h1>
                    <p class="body-muted">
                        Seluruh atribut termasuk <strong>Primary Key ID</strong>, kode tiket, dan isi laporan dienkripsi menggunakan <strong>AES-256-CBC + RSA-2048</strong> sebelum masuk ke database.
                    </p>
                </div>

                <form method="POST" class="admin-input-grid">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                    <input type="hidden" name="action" value="save_report">

                    <div class="form-group">
                        <label for="reporter_alias" class="form-label">Kode / Alias Sumber Informasi</label>
                        <input type="text" id="reporter_alias" name="reporter_alias" class="form-control" placeholder="Contoh: Saksi Internal / Anonim">
                    </div>

                    <div class="form-group">
                        <label for="category" class="form-label">Kategori Pelanggaran</label>
                        <select id="category" name="category" class="form-control" required>
                            <option value="Plagiarisme & Kecurangan Akademik">Plagiarisme &amp; Kecurangan Akademik</option>
                            <option value="Gratifikasi & Penyalahgunaan Wewenang">Gratifikasi &amp; Penyalahgunaan Wewenang</option>
                            <option value="Perundungan & Etika Kampus">Perundungan &amp; Etika Kampus</option>
                            <option value="Kebocoran Data & Keamanan Sistem">Kebocoran Data &amp; Keamanan Sistem</option>
                        </select>
                    </div>

                    <div class="form-group grid-span-full">
                        <label for="subject" class="form-label">Subjek Laporan Rahasia</label>
                        <input type="text" id="subject" name="subject" class="form-control" placeholder="Ringkasan singkat kasus atau temuan" required>
                    </div>

                    <div class="form-group grid-span-full">
                        <label for="chronology" class="form-label">Kronologi Lengkap (Akan Dienkripsi Otomatis)</label>
                        <textarea id="chronology" name="chronology" class="form-control" rows="3" placeholder="Tuliskan detail laporan rahasia yang akan diamankan di database..." required></textarea>
                    </div>

                    <div class="grid-span-full">
                        <button type="submit" class="btn btn-primary">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            </svg>
                            <span>Enkripsi &amp; Simpan ke Database</span>
                        </button>
                    </div>
                </form>
            </section>
        <?php endif; ?>

        <!-- Section 2: All Stored Encrypted Content -->
        <section class="vault-section" aria-labelledby="vault-heading">
            <div class="dashboard-topbar">
                <div>
                    <span class="eyebrow"><?= renderUiText('02 / Seluruh Konten Hasil Enkripsi', $isVerified) ?></span>
                    <h2 id="vault-heading" class="section-title">
                        <?= renderUiText('Rekaman Terenkripsi Tersimpan (' . count($records) . ')', $isVerified) ?>
                    </h2>
                    <p class="body-muted">
                        <?= renderUiText('Menampilkan seluruh konten hasil enkripsi termasuk Encrypted ID di database beserta hasil dekripsinya.', $isVerified) ?>
                    </p>
                </div>

                <?php if ($isVerified && !empty($records)): ?>
                    <div class="view-switcher">
                        <a href="admin.php" class="btn <?= !$cipherOnlyMode ? 'btn-primary' : 'btn-secondary' ?> btn-sm">
                            Enkripsi + Dekripsi
                        </a>
                        <a href="admin.php?view=cipher" class="btn <?= $cipherOnlyMode ? 'btn-primary' : 'btn-secondary' ?> btn-sm">
                            Hanya Ciphertext Database
                        </a>
                        <form method="POST" class="inline-form" data-confirm-form data-confirm-title="Hapus Semua Laporan?" data-confirm-message="Seluruh <?= count($records) ?> rekaman terenkripsi akan dihapus permanen.">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                            <input type="hidden" name="action" value="delete_all">
                            <button type="submit" class="btn btn-danger btn-sm">Hapus Semua</button>
                        </form>
                    </div>
                <?php endif; ?>
            </div>

            <?php if (empty($records)): ?>
                <div class="card empty-state">
                    <h3 class="section-title"><?= renderUiText('Belum Ada Laporan Terenkripsi', $isVerified) ?></h3>
                    <p class="body-muted"><?= renderUiText('Gunakan formulir di atas untuk menginput dan mengenkripsi laporan rahasia pertama.', $isVerified) ?></p>
                </div>
            <?php else: ?>
                <div class="records-list">
                    <?php foreach ($records as $row): ?>
                        <?php
                        $decryptedId = ($isVerified && !$cipherOnlyMode)
                            ? decryptSingleCipher($row['id'], $row['encrypted_aes_key'], $row['iv_base64'], $privateKeyPem)
                            : null;
                        $decrypted = ($isVerified && !$cipherOnlyMode)
                            ? hybridDecryptPayload($row['ciphertext'], $row['encrypted_aes_key'], $row['iv_base64'], $privateKeyPem)
                            : null;
                        ?>
                        <article class="card record-card">
                            <div class="record-meta">
                                <div class="record-id-group">
                                    <span class="code-pill mono-text">
                                        <?= ($decryptedId !== null && $decrypted !== null)
                                            ? htmlspecialchars(($decrypted['report_code'] ?? '') . ' • ' . $decryptedId)
                                            : htmlspecialchars($row['id']) ?>
                                    </span>
                                    <span class="algo-tag mono-text"><?= renderUiText($row['cipher_algo'], $isVerified) ?></span>
                                </div>
                                <div class="record-actions">
                                    <time class="timestamp mono-text"><?= renderUiText($row['created_at'], $isVerified) ?></time>
                                    <?php if ($isVerified): ?>
                                        <form method="POST" class="inline-form" data-confirm-form data-confirm-title="Hapus Rekaman Ini?" data-confirm-message="Rekaman terenkripsi ini akan dihapus permanen dari database.">
                                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                            <input type="hidden" name="action" value="delete_single">
                                            <input type="hidden" name="report_id" value="<?= htmlspecialchars($row['id']) ?>">
                                            <button type="submit" class="btn btn-danger btn-sm">Hapus Pesan</button>
                                        </form>
                                    <?php endif; ?>
                                </div>
                            </div>

                            <!-- Decrypted Plaintext Panel -->
                            <?php if ($isVerified && !$cipherOnlyMode): ?>
                                <?php if ($decrypted !== null): ?>
                                    <div class="decrypted-panel">
                                        <div class="decrypted-header">
                                            <span class="badge-verified">Terdekripsi</span>
                                            <span class="meta-item">ID Asli: <strong><?= htmlspecialchars($decryptedId ?? '-') ?></strong></span>
                                            <span class="meta-item">Sumber: <strong><?= htmlspecialchars($decrypted['reporter_alias'] ?? 'Anonim') ?></strong></span>
                                            <span class="meta-item">Kategori: <strong><?= htmlspecialchars($decrypted['category'] ?? '-') ?></strong></span>
                                        </div>
                                        <h3 class="decrypted-subject"><?= htmlspecialchars($decrypted['subject'] ?? '') ?></h3>
                                        <p class="decrypted-body"><?= nl2br(htmlspecialchars($decrypted['chronology'] ?? '')) ?></p>
                                    </div>
                                <?php else: ?>
                                    <div class="alert alert-error" role="alert">
                                        Data ini dikunci menggunakan <code>public.pem</code> versi lama sebelum kunci di-generate ulang. Klik <strong>Hapus Pesan</strong> untuk membersihkannya.
                                    </div>
                                <?php endif; ?>
                            <?php endif; ?>

                            <!-- Stored Encrypted Content -->
                            <div class="encrypted-grid">
                                <div class="cipher-field">
                                    <span class="field-label"><?= renderUiText('Encrypted Primary Key ID (AES-256 Base64)', $isVerified) ?></span>
                                    <pre class="mono-box"><?= htmlspecialchars($row['id']) ?></pre>
                                </div>
                                <div class="cipher-field">
                                    <span class="field-label"><?= renderUiText('Encrypted Report Code (AES-256 Base64)', $isVerified) ?></span>
                                    <pre class="mono-box"><?= htmlspecialchars($row['report_code']) ?></pre>
                                </div>
                                <div class="cipher-field">
                                    <span class="field-label"><?= renderUiText('Ciphertext Isi Laporan (AES-256-CBC Base64)', $isVerified) ?></span>
                                    <pre class="mono-box"><?= htmlspecialchars($row['ciphertext']) ?></pre>
                                </div>
                                <div class="cipher-field">
                                    <span class="field-label"><?= renderUiText('Encrypted Session Key (RSA-2048 OAEP)', $isVerified) ?></span>
                                    <pre class="mono-box"><?= htmlspecialchars($row['encrypted_aes_key']) ?></pre>
                                </div>
                                <div class="cipher-field grid-span-full">
                                    <span class="field-label"><?= renderUiText('Initialization Vector (IV)', $isVerified) ?></span>
                                    <code class="mono-inline"><?= htmlspecialchars($row['iv_base64']) ?></code>
                                </div>
                            </div>
                        </article>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </section>
    </main>

    <!-- Confirmation Dialog -->
    <dialog id="confirm-dialog" class="confirm-dialog" aria-labelledby="confirm-dialog-title" aria-describedby="confirm-dialog-desc">
        <div class="confirm-dialog-body">
            <span class="eyebrow">Konfirmasi Penghapusan</span>
            <h2 id="confirm-dialog-title" class="section-title">Hapus Pesan?</h2>
            <p id="confirm-dialog-desc" class="body-muted">Rekaman terenkripsi akan dihapus permanen dari database.</p>
            <div class="confirm-dialog-actions">
                <button type="button" id="confirm-cancel-btn" class="btn btn-secondary btn-sm">Batal</button>
                <button type="button" id="confirm-proceed-btn" class="btn btn-danger-solid btn-sm">Ya, Hapus</button>
            </div>
        </div>
    </dialog>

    <footer class="site-footer">
        <div class="container footer-inner">
            <span><?= renderUiText('SIPELOR Admin Vault • Login pukul ' . ($_SESSION['login_time'] ?? '-'), $isVerified) ?></span>
            <span><?= renderUiText('Kunci dekripsi hanya berada di sesi memori aktif', $isVerified) ?></span>
        </div>
    </footer>

    <script src="assets/js/app.js"></script>
</body>
</html>