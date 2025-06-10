<?php
session_start();
require_once '../config/database.php';
require_once '../security/asymmetric/ecc_encryption.php';
require_once '../security/key_management.php';
require_once '../security/asymmetric/ntru_encryption.php';

// Add this temporarily at the top of register.php to check OpenSSL
// echo "OpenSSL version: " . OPENSSL_VERSION_TEXT . "<br>";
// echo "OpenSSL loaded: " . (extension_loaded('openssl') ? 'Yes' : 'No') . "<br>";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
    $name = $_POST['name'];
    $phone_number = $_POST['phone_number'];
    $address = $_POST['address'];
    $social_security_number = $_POST['social_security_number'];
    $email = $_POST['email'];

    try {
        // First insert the user to get the user ID
        $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
        $stmt->execute([
            'username' => $username,
            'password' => $password
        ]);
        
        $userId = $pdo->lastInsertId();
        
        // Use absolute path for keys directory
        $keyStorePath = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'keys';
        $keyManager = new KeyManagement($keyStorePath);
        
        try {
            $keys = $keyManager->generateUserKeys($userId);
        } catch (Exception $e) {
            // If key generation fails, delete the user and throw error
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = :id");
            $stmt->execute(['id' => $userId]);
            throw new Exception("Key generation failed: " . $e->getMessage());
        }
        
        // Use NTRU for highly sensitive data
        $ntru = new NTRUEncryption();
        $encryptedSSN = $ntru->encrypt($social_security_number, $keys['ntru']['public']);
        $encryptedPII = $ntru->encrypt($name, $keys['ntru']['public']);
        $encryptedAddress = $ntru->encrypt($address, $keys['ntru']['public']);
        
        // Use ECC for less sensitive data or session-based data
        $ecc = new ECCEncryption();
        $encryptedEmail = $ecc->encrypt($email, $keys['ecc']['public']);
        $encryptedPreferences = $ecc->encrypt($phone_number, $keys['ecc']['public']);
        
        // Update user record with encrypted data
        $stmt = $pdo->prepare("UPDATE users SET 
            name = :name,
            phone_number = :phone_number,
            address = :address,
            social_security_number = :social_security_number,
            email = :email
            WHERE id = :id");
            
        $stmt->execute([
            'id' => $userId,
            'name' => $encryptedPII,
            'phone_number' => $encryptedPreferences,
            'address' => $encryptedAddress,
            'social_security_number' => $encryptedSSN,
            'email' => $encryptedEmail
        ]);
        
        header('Location: login.php');
        exit();
    } catch (Exception $e) {
        error_log("Registration error: " . $e->getMessage());
        $error = "Error during registration: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register | Secure App</title>
    <link rel="stylesheet" href="app/frontpage.css">
</head>
<body>
    <div class="container">
        <h1>Input your personal information</h1>
        
        <?php if (isset($error)): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <div class="field-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Choose a username" required>
            </div>
            
            <div class="field-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Choose a strong password" required>
            </div>
            
            <div class="field-group">
                <label for="name">Full Name</label>
                <input type="text" id="name" name="name" placeholder="Enter your full name" required>
            </div>
            
            <div class="field-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" placeholder="Enter your email address" required>
            </div>
            
            <div class="field-group">
                <label for="phone_number">Phone Number</label>
                <input type="tel" id="phone_number" name="phone_number" placeholder="Enter your phone number" required>
            </div>
            
            <div class="field-group address-field">
                <label for="address">Address</label>
                <textarea id="address" name="address" placeholder="Enter your full address" required></textarea>
            </div>
            
            <div class="field-group">
                <label for="social_security_number">Social Security Number</label>
                <input type="text" id="social_security_number" name="social_security_number" 
                       class="sensitive-field" placeholder="XXX-XX-XXXX" required>
            </div>
            
            <button type="submit">Submit</button>
        </form>
        
        <p>Already have an account? <a href="login.php">Login here</a></p>
        
        <hr>
        
        <div class="security-info">
            Your personal information is protected with advanced encryption technologies
        </div>
    </div>
</body>
</html>