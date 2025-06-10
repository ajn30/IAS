<?php
require_once '../security/homomorphic/homomorphic_key_management.php';
require_once '../security/homomorphic/paillier_encryption.php';

// Initialize homomorphic key management
$keyManager = new HomomorphicKeyManagement();

// Generate keys for a user
$userId = 1;
$keys = $keyManager->generateUserKeys($userId);

if (!$keys || !isset($keys['public'], $keys['private'])) {
    die('<b>Error:</b> Failed to generate or retrieve user keys.');
}

// Get Paillier instance
$paillier = new PaillierEncryption();

// Example values
$value1 = 10;
$value2 = 100;
$value3 = 55;

// Encrypt values
$encrypted1 = $paillier->encrypt($value1, $keys['public']);
$encrypted2 = $paillier->encrypt($value2, $keys['public']);
$encrypted3 = $paillier->encrypt($value3, $keys['public']);

if (!$encrypted1 || !$encrypted2 || !$encrypted3) {
    die('<b>Error:</b> Encryption failed.');
}

// Perform homomorphic addition: ((value1 + value2) + value3)
$encryptedSum12 = $paillier->addEncrypted($encrypted1, $encrypted2, $keys['public']);
$encryptedSum = $paillier->addEncrypted($encryptedSum12, $encrypted3, $keys['public']);

// Decrypt the result
$sum = $paillier->decrypt($encryptedSum, $keys['private'], $keys['public']);

// Output results in HTML
echo '<!DOCTYPE html><html><head><title>Homomorphic Encryption Example</title></head><body>';
echo '<h2>Homomorphic Encryption Example</h2>';
echo '<ul>';
echo '<li>Value 1: ' . htmlspecialchars($value1) . '</li>';
echo '<li>Value 2: ' . htmlspecialchars($value2) . '</li>';
echo '<li>Value 3: ' . htmlspecialchars($value3) . '</li>';
echo '</ul>';
echo '<h3>Encrypted Values</h3>';
echo '<ul>';
echo '<li>Encrypted 1: <code>' . htmlspecialchars($encrypted1) . '</code></li>';
echo '<li>Encrypted 2: <code>' . htmlspecialchars($encrypted2) . '</code></li>';
echo '<li>Encrypted 3: <code>' . htmlspecialchars($encrypted3) . '</code></li>';
echo '</ul>';
echo '<h3>Homomorphic Addition</h3>';
echo '<ul>';
echo '<li>Encrypted Sum: <code>' . htmlspecialchars($encryptedSum) . '</code></li>';
echo '<li>Decrypted Sum: <b>' . htmlspecialchars($sum) . '</b></li>';
echo '</ul>';
echo '</body></html>';
?> 