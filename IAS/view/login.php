<?php
session_start();
require_once '../config/database.php';
require_once '../security/asymmetric/ntru_encryption.php';
require_once '../security/key_management.php';
require_once '../security/asymmetric/ecc_encryption.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            
            // Initialize key management and encryption
            $keyManager = new KeyManagement();
            $ntru = new NTRUEncryption();
            $ecc = new ECCEncryption();
            
            try {
                // Get keys
                $ntruKeys = $keyManager->getNTRUKeys($user['id']);
                $eccKeys = $keyManager->getECCKeys($user['id']);
                
                // Decrypt NTRU-encrypted data
                if (!empty($user['social_security_number'])) {
                    try {
                        $_SESSION['social_security_number'] = $ntru->decrypt($user['social_security_number'], $ntruKeys['private']);
                    } catch (Exception $e) {
                        error_log("Failed to decrypt SSN: " . $e->getMessage());
                    }
                }
                if (!empty($user['name'])) {
                    try {
                        $_SESSION['name'] = $ntru->decrypt($user['name'], $ntruKeys['private']);
                    } catch (Exception $e) {
                        error_log("Failed to decrypt name: " . $e->getMessage());
                    }
                }
                if (!empty($user['address'])) {
                    try {
                        $_SESSION['address'] = $ntru->decrypt($user['address'], $ntruKeys['private']);
                    } catch (Exception $e) {
                        error_log("Failed to decrypt address: " . $e->getMessage());
                    }
                }
                
                // Decrypt ECC-encrypted data
                if (!empty($user['email'])) {
                    $_SESSION['email'] = $ecc->decrypt($user['email'], $eccKeys['private']);
                }
                if (!empty($user['phone_number'])) {
                    $_SESSION['phone_number'] = $ecc->decrypt($user['phone_number'], $eccKeys['private']);
                }
                
                header('Location: dashboard.php');
                exit();
            } catch (Exception $e) {
                error_log("Decryption error: " . $e->getMessage());
                $error = "Error decrypting user data: " . $e->getMessage();
            }
        } else {
            $error = "Invalid username or password.";
        }
    } catch (Exception $e) {
        error_log("Login error: " . $e->getMessage());
        $error = "Error during login: " . $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | Secure App</title>
    <link rel="stylesheet" href="app/frontpage.css">
</head>
<body>
    <div class="container">
        <h1>Welcome Back</h1>
        
        <?php if (isset($error)): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <div class="field-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter your username" required>
            </div>
            
            <div class="field-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            
            <button type="submit">Log In</button>
        </form>
        
        <p>Don't have an account? <a href="register.php">Registration</a></p>
        
        <hr>
        
        <div class="security-info">
            This application uses advanced encryption to protect your personal information
        </div>
    </div>
</body>
</html>