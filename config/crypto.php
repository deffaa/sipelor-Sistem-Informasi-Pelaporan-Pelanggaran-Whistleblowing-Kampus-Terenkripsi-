<?php
declare(strict_types=1);

define('KEYS_DIR', __DIR__ . '/../keys');
define('PUBLIC_KEY_PATH', KEYS_DIR . '/public.pem');
define('SYMMETRIC_HASH_PATH', KEYS_DIR . '/symmetric.hash');

/**
 * Locate openssl.cnf on Windows/Laragon automatically.
 */
function getOpenSslConfig(): array
{
    $candidates = [getenv('OPENSSL_CONF') ?: ''];
    $laragonPhp = glob('C:/laragon/bin/php/*/extras/ssl/openssl.cnf') ?: [];
    $laragonApache = glob('C:/laragon/bin/apache/*/conf/openssl.cnf') ?: [];

    foreach (array_merge($candidates, $laragonPhp, $laragonApache) as $path) {
        if ($path !== '' && file_exists($path)) {
            return [
                'config'           => $path,
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ];
        }
    }

    return [
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];
}

/**
 * Check whether RSA public key and symmetric hash exist on server.
 */
function isSystemInitialized(): bool
{
    return file_exists(PUBLIC_KEY_PATH) && file_exists(SYMMETRIC_HASH_PATH);
}

/**
 * Generate a new RSA-2048 key pair and 256-bit Symmetric Key.
 */
function generateSystemKeys(): array
{
    if (!extension_loaded('openssl')) {
        throw new RuntimeException('Ekstensi OpenSSL belum aktif di PHP Laragon.');
    }

    if (!is_dir(KEYS_DIR)) {
        mkdir(KEYS_DIR, 0755, true);
    }

    $config = getOpenSslConfig();
    $res = openssl_pkey_new($config);
    if ($res === false) {
        throw new RuntimeException('Gagal membuat pasangan kunci RSA: ' . (openssl_error_string() ?: 'openssl.cnf tidak ditemukan'));
    }

    openssl_pkey_export($res, $privateKeyPem, null, $config);
    $details = openssl_pkey_get_details($resource ?? $res);
    $publicKeyPem = $details['key'];

    $symmetricKey = bin2hex(random_bytes(32));

    file_put_contents(PUBLIC_KEY_PATH, $publicKeyPem);
    file_put_contents(SYMMETRIC_HASH_PATH, hash('sha256', $symmetricKey));

    return [
        'symmetric_key' => $symmetricKey,
        'private_key'   => $privateKeyPem,
    ];
}

/**
 * Encrypt ID, report code, and JSON payload using Hybrid Cryptography (AES-256-CBC + RSA-2048).
 */
function hybridEncryptPayload(array $payload, string $plainId, string $plainReportCode): array
{
    if (!isSystemInitialized()) {
        throw new RuntimeException('Kunci kriptografi belum diinisialisasi.');
    }

    $publicKey = openssl_pkey_get_public((string) file_get_contents(PUBLIC_KEY_PATH));
    if ($publicKey === false) {
        throw new RuntimeException('Public key RSA tidak valid.');
    }

    // 1. Generate random 256-bit AES session key & 128-bit IV
    $aesKey = random_bytes(32);
    $iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));

    // 2. Encrypt ID, Report Code, and Payload symmetrically with AES-256-CBC
    $rawEncryptedId = openssl_encrypt($plainId, 'aes-256-cbc', $aesKey, OPENSSL_RAW_DATA, $iv);
    $rawEncryptedCode = openssl_encrypt($plainReportCode, 'aes-256-cbc', $aesKey, OPENSSL_RAW_DATA, $iv);
    $jsonPlaintext = json_encode($payload, JSON_UNESCAPED_UNICODE);
    $rawCiphertext = openssl_encrypt($jsonPlaintext, 'aes-256-cbc', $aesKey, OPENSSL_RAW_DATA, $iv);

    if ($rawEncryptedId === false || $rawEncryptedCode === false || $rawCiphertext === false) {
        throw new RuntimeException('Enkripsi simetris AES-256 gagal.');
    }

    // 3. Encrypt the AES session key asymmetrically with RSA Public Key
    $encryptedAesKey = '';
    if (!openssl_public_encrypt($aesKey, $encryptedAesKey, $publicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        throw new RuntimeException('Enkripsi asimetris kunci sesi RSA gagal.');
    }

    return [
        'encrypted_id'      => base64_encode($rawEncryptedId),
        'encrypted_code'    => base64_encode($rawEncryptedCode),
        'ciphertext'        => base64_encode($rawCiphertext),
        'encrypted_aes_key' => base64_encode($encryptedAesKey),
        'iv_base64'         => base64_encode($iv),
    ];
}

/**
 * Verify Admin login using Symmetric Key + Asymmetric Private Key.
 */
function verifyDualKeyLogin(string $symmetricKeyInput, string $privateKeyPemInput): bool
{
    if (!isSystemInitialized()) {
        return false;
    }

    $symmetricKeyInput = trim($symmetricKeyInput);
    $privateKeyPemInput = trim($privateKeyPemInput);

    if ($symmetricKeyInput === '' || $privateKeyPemInput === '') {
        return false;
    }

    $storedHash = trim((string) file_get_contents(SYMMETRIC_HASH_PATH));
    if (!hash_equals($storedHash, hash('sha256', $symmetricKeyInput))) {
        return false;
    }

    $publicKey = openssl_pkey_get_public((string) file_get_contents(PUBLIC_KEY_PATH));
    $privateKey = openssl_pkey_get_private($privateKeyPemInput);

    if ($publicKey === false || $privateKey === false) {
        return false;
    }

    $challenge = random_bytes(32);
    $encryptedChallenge = '';
    $decryptedChallenge = '';

    if (!openssl_public_encrypt($challenge, $encryptedChallenge, $publicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        return false;
    }

    if (!openssl_private_decrypt($encryptedChallenge, $decryptedChallenge, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        return false;
    }

    return hash_equals($challenge, $decryptedChallenge);
}

/**
 * Unwrap AES session key and decrypt a single Base64 ciphertext field (such as encrypted ID).
 */
function decryptSingleCipher(string $cipherB64, string $encryptedAesKeyB64, string $ivB64, string $privateKeyPem): ?string
{
    $privateKey = openssl_pkey_get_private($privateKeyPem);
    if ($privateKey === false) {
        return null;
    }

    $encryptedAesKey = base64_decode($encryptedAesKeyB64, true);
    $rawCipher = base64_decode($cipherB64, true);
    $iv = base64_decode($ivB64, true);

    if ($encryptedAesKey === false || $rawCipher === false || $iv === false) {
        return null;
    }

    $aesKey = '';
    if (!openssl_private_decrypt($encryptedAesKey, $aesKey, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        return null;
    }

    $plain = openssl_decrypt($rawCipher, 'aes-256-cbc', $aesKey, OPENSSL_RAW_DATA, $iv);
    return $plain !== false ? $plain : null;
}

/**
 * Decrypt stored JSON payload ciphertext using the authenticated Admin Private Key.
 */
function hybridDecryptPayload(string $ciphertextB64, string $encryptedAesKeyB64, string $ivB64, string $privateKeyPem): ?array
{
    $jsonPlaintext = decryptSingleCipher($ciphertextB64, $encryptedAesKeyB64, $ivB64, $privateKeyPem);
    if ($jsonPlaintext === null) {
        return null;
    }

    $data = json_decode($jsonPlaintext, true);
    return is_array($data) ? $data : null;
}

/**
 * Render readable UI text when verified, or AES-256 Base64 ciphertext when Private Key is wrong.
 */
function renderUiText(string $plainText, bool $isVerified): string
{
    if ($isVerified) {
        return htmlspecialchars($plainText, ENT_QUOTES, 'UTF-8');
    }

    $cipher = openssl_encrypt($plainText, 'aes-256-cbc', random_bytes(32), OPENSSL_RAW_DATA, random_bytes(16));
    return htmlspecialchars(base64_encode($cipher ?: random_bytes(16)), ENT_QUOTES, 'UTF-8');
}