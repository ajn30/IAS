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
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #2980b9 0%, #6dd5fa 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .register-card {
            background: #fff;
            border-radius: 16px;
            box-shadow: 0 8px 32px rgba(44, 62, 80, 0.15);
            padding: 40px 32px 32px 32px;
            max-width: 480px;
            width: 100%;
            margin: 30px 10px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .register-card .avatar {
            width: 70px;
            height: 70px;
            border-radius: 50%;
            background: #eaf6fb;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            color: #2980b9;
            margin-bottom: 18px;
        }
        .register-card h1 {
            color: #2980b9;
            font-size: 2rem;
            margin-bottom: 18px;
            font-weight: 700;
            text-align: center;
        }
        .error {
            background: #ffebee;
            color: #c62828;
            padding: 12px 18px;
            border-radius: 6px;
            margin-bottom: 18px;
            border-left: 4px solid #c62828;
            width: 100%;
            font-size: 1rem;
        }
        form {
            width: 100%;
            display: flex;
            flex-direction: column;
        }
        .field-group {
            margin-bottom: 18px;
            position: relative;
        }
        .field-group label {
            font-weight: 600;
            color: #555;
            margin-bottom: 6px;
            display: block;
        }
        .field-group .fa-solid {
            position: absolute;
            left: 12px;
            top: 38px;
            color: #b2bec3;
            font-size: 1.1rem;
        }
        .field-group input,
        .field-group textarea {
            width: 100%;
            padding: 12px 12px 12px 38px;
            border: 1px solid #d0e6f6;
            border-radius: 6px;
            font-size: 1rem;
            background: #f8fbfd;
            transition: border-color 0.3s;
            resize: none;
        }
        .field-group textarea {
            min-height: 60px;
        }
        .field-group input:focus,
        .field-group textarea:focus {
            border-color: #2980b9;
            outline: none;
        }
        button[type="submit"] {
            background: linear-gradient(90deg, #2980b9 0%, #6dd5fa 100%);
            color: #fff;
            border: none;
            padding: 12px 0;
            border-radius: 6px;
            font-size: 1.1rem;
            font-weight: 700;
            cursor: pointer;
            margin-top: 8px;
            box-shadow: 0 2px 8px rgba(52, 152, 219, 0.08);
            transition: background 0.2s;
        }
        button[type="submit"]:hover {
            background: linear-gradient(90deg, #2574a9 0%, #48b1f3 100%);
        }
        .register-card p {
            margin-top: 18px;
            font-size: 1rem;
            color: #555;
        }
        .register-card a {
            color: #2980b9;
            text-decoration: none;
            font-weight: 600;
        }
        .register-card a:hover {
            text-decoration: underline;
        }
        hr {
            margin: 28px 0 18px 0;
            border: none;
            border-top: 1px solid #e3eaf1;
            width: 100%;
        }
        .security-info {
            background: #eaf6fb;
            color: #2980b9;
            padding: 12px 18px;
            border-radius: 6px;
            font-size: 0.98rem;
            text-align: center;
            margin-top: 0;
        }
        @media (max-width: 600px) {
            .register-card {
                padding: 24px 6px 18px 6px;
            }
        }
    </style>
</head>
<body>
    <div class="register-card">
        <div class="avatar">
            <i class="fa-solid fa-user-plus"></i>
        </div>
        <h1>Input your personal information</h1>
        <?php if (isset($error)): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <form method="POST" action="">
            <div class="field-group">
                <label for="username">Username</label>
                <i class="fa-solid fa-user"></i>
                <input type="text" id="username" name="username" placeholder="Choose a username" required>
            </div>
            <div class="field-group">
                <label for="password">Password</label>
                <i class="fa-solid fa-lock"></i>
                <input type="password" id="password" name="password" placeholder="Choose a strong password" required>
            </div>
            <div class="field-group">
                <label for="name">Full Name</label>
                <i class="fa-solid fa-id-card"></i>
                <input type="text" id="name" name="name" placeholder="Enter your full name" required>
            </div>
            <div class="field-group">
                <label for="email">Email Address</label>
                <i class="fa-solid fa-envelope"></i>
                <input type="email" id="email" name="email" placeholder="Enter your email address" required>
            </div>
            <div class="field-group">
                <label for="phone_number">Phone Number</label>
                <i class="fa-solid fa-phone"></i>
                <input type="tel" id="phone_number" name="phone_number" placeholder="Enter your phone number" required>
            </div>
            <div class="field-group address-field">
                <label for="address">Address</label>
                <i class="fa-solid fa-location-dot"></i>
                <textarea id="address" name="address" placeholder="Enter your full address" required></textarea>
            </div>
            <div class="field-group">
                <label for="social_security_number">Social Security Number</label>
                <i class="fa-solid fa-id-badge"></i>
                <input type="text" id="social_security_number" name="social_security_number" 
                       class="sensitive-field" placeholder="XXX-XX-XXXX" required>
            </div>
            <button type="submit"><i class="fa-solid fa-paper-plane"></i> Submit</button>
        </form>
        <p>Already have an account? <a href="login.php">Login here</a></p>
        <hr>
        <div class="security-info">
            <i class="fa-solid fa-lock"></i> Your personal information is protected with advanced encryption technologies
        </div>
    </div>
</body>
</html>