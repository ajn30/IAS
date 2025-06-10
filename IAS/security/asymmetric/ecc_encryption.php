<?php
require_once __DIR__ . '/../symmetric/aes_gcm.php';
require_once __DIR__ . '/../symmetric/chacha20.php';

class ECCEncryption {
    private $cipherMode = 'AES-256-GCM';
    private $aesGcm;
    private $chaCha20;
    private $curve = 'prime256v1'; // NIST P-256 curve, widely supported
    
    public function __construct($mode = 'AES-256-GCM') {
        $allowedModes = ['AES-256-GCM', 'CHACHA20'];
        if (in_array($mode, $allowedModes)) {
            $this->cipherMode = $mode;
        }
        $this->aesGcm = new AES_GCM_Encryption();
        $this->chaCha20 = new ChaCha20_Encryption();
    }
    
    // Generate ECC key pair
    public function generateKeyPair() {
        try {
            // Check OpenSSL extension
            if (!extension_loaded('openssl')) {
                throw new Exception("OpenSSL extension is not loaded");
            }

            // Windows-compatible configuration for ECC
            $config = array(
                "config" => "C:/xampp/php/extras/openssl/openssl.cnf",
                "private_key_type" => OPENSSL_KEYTYPE_EC,
                "curve_name" => $this->curve
            );

            // Try to find OpenSSL config file
            $possiblePaths = [
                "C:/xampp/php/extras/openssl/openssl.cnf",
                "C:/xampp/apache/conf/openssl.cnf",
                php_ini_loaded_file() ? dirname(php_ini_loaded_file()) . '/openssl.cnf' : null
            ];

            foreach ($possiblePaths as $path) {
                if ($path && file_exists($path)) {
                    $config['config'] = $path;
                    break;
                }
            }

            // Generate ECC private key
            $privateKey = openssl_pkey_new($config);
            
            if ($privateKey === false) {
                // If failed with config, try without it
                unset($config['config']);
                $privateKey = openssl_pkey_new($config);
                
                if ($privateKey === false) {
                    throw new Exception("Failed to generate ECC key: " . openssl_error_string());
                }
            }

            // Export private key
            if (!openssl_pkey_export($privateKey, $privateKeyPem, null, $config)) {
                throw new Exception("Failed to export ECC private key: " . openssl_error_string());
            }

            // Get public key
            $keyDetails = openssl_pkey_get_details($privateKey);
            if ($keyDetails === false) {
                throw new Exception("Failed to get ECC key details: " . openssl_error_string());
            }

            return [
                'private' => $privateKeyPem,
                'public' => $keyDetails['key']
            ];

        } catch (Exception $e) {
            error_log("ECC key generation error: " . $e->getMessage());
            throw new Exception("ECC key generation failed: " . $e->getMessage());
        }
    }

    // ECDH key agreement
    private function deriveSharedSecret($privateKey, $publicKey) {
        try {
            // Get private key resource
            $privKey = openssl_pkey_get_private($privateKey);
            if ($privKey === false) {
                throw new Exception("Invalid ECC private key");
            }

            // Get public key resource
            $pubKey = openssl_pkey_get_public($publicKey);
            if ($pubKey === false) {
                throw new Exception("Invalid ECC public key");
            }

            // Perform ECDH to derive shared secret
            $sharedSecret = openssl_pkey_derive($pubKey, $privKey);
            if ($sharedSecret === false) {
                throw new Exception("Failed to derive ECDH shared secret: " . openssl_error_string());
            }

            // Hash the shared secret to get a symmetric key
            return hash('sha256', $sharedSecret, true);

        } catch (Exception $e) {
            throw new Exception("ECDH key agreement failed: " . $e->getMessage());
        }
    }
    
    // Encrypt data using ECIES (Elliptic Curve Integrated Encryption Scheme)
    public function encrypt($data, $recipientPublicKey) {
        try {
            // Generate ephemeral ECC key pair for this encryption
            $ephemeralKeyPair = $this->generateKeyPair();
            
            // Derive shared secret using ECDH
            $sharedSecret = $this->deriveSharedSecret(
                $ephemeralKeyPair['private'],
                $recipientPublicKey
            );
            
            // Generate IV
            $iv = random_bytes(12); // 12 bytes for GCM and ChaCha20
            
            // Encrypt data using symmetric encryption
            switch ($this->cipherMode) {
                case 'AES-256-GCM':
                    $result = $this->aesGcm->encrypt($data, $sharedSecret, $iv);
                    $package = [
                        'mode' => 'AES-256-GCM',
                        'ephemeral_public_key' => base64_encode($ephemeralKeyPair['public']),
                        'iv' => base64_encode($iv),
                        'tag' => $result['tag'],
                        'data' => $result['ciphertext']
                    ];
                    break;
                    
                case 'CHACHA20':
                    $encryptedData = $this->chaCha20->encrypt($data, $sharedSecret, $iv);
                    $package = [
                        'mode' => 'CHACHA20',
                        'ephemeral_public_key' => base64_encode($ephemeralKeyPair['public']),
                        'nonce' => base64_encode($iv),
                        'data' => $encryptedData
                    ];
                    break;
            }
            
            return base64_encode(json_encode($package));
        } catch (Exception $e) {
            throw new Exception("ECIES encryption failed: " . $e->getMessage());
        }
    }
    
    // Decrypt data using ECIES
    public function decrypt($encryptedPackage, $recipientPrivateKey) {
        try {
            $package = json_decode(base64_decode($encryptedPackage), true);
            if (!$package || !isset($package['mode'])) {
                throw new Exception("Invalid encrypted package format");
            }
            
            // Get ephemeral public key
            $ephemeralPublicKey = base64_decode($package['ephemeral_public_key']);
            
            // Derive shared secret using ECDH
            $sharedSecret = $this->deriveSharedSecret(
                $recipientPrivateKey,
                $ephemeralPublicKey
            );
            
            // Decrypt data based on mode
            switch ($package['mode']) {
                case 'AES-256-GCM':
                    $iv = base64_decode($package['iv']);
                    $decryptedData = $this->aesGcm->decrypt(
                        $package['data'],
                        $sharedSecret,
                        $iv,
                        $package['tag']
                    );
                    break;
                    
                case 'CHACHA20':
                    $nonce = base64_decode($package['nonce']);
                    $decryptedData = $this->chaCha20->decrypt(
                        $package['data'],
                        $sharedSecret,
                        $nonce
                    );
                    break;
                
                default:
                    throw new Exception("Unsupported encryption mode");
            }
            
            if ($decryptedData === false) {
                throw new Exception("Failed to decrypt data");
            }
            
            return $decryptedData;
        } catch (Exception $e) {
            throw new Exception("ECIES decryption failed: " . $e->getMessage());
        }
    }
}
?> 