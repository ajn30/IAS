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
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #2980b9 0%, #6dd5fa 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: #fff;
            border-radius: 16px;
            box-shadow: 0 8px 32px rgba(44, 62, 80, 0.15);
            padding: 40px 32px 32px 32px;
            max-width: 400px;
            width: 100%;
            margin: 30px 10px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .login-card .avatar {
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
        .login-card h1 {
            color: #2980b9;
            font-size: 2rem;
            margin-bottom: 18px;
            font-weight: 700;
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
        .field-group input {
            width: 100%;
            padding: 12px 12px 12px 38px;
            border: 1px solid #d0e6f6;
            border-radius: 6px;
            font-size: 1rem;
            background: #f8fbfd;
            transition: border-color 0.3s;
        }
        .field-group input:focus {
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
        .login-card p {
            margin-top: 18px;
            font-size: 1rem;
            color: #555;
        }
        .login-card a {
            color: #2980b9;
            text-decoration: none;
            font-weight: 600;
        }
        .login-card a:hover {
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
        @media (max-width: 500px) {
            .login-card {
                padding: 24px 6px 18px 6px;
            }
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="avatar">
            <i class="fa-solid fa-shield-halved"></i>
        </div>
        <h1>Welcome Back</h1>
        <?php if (isset($error)): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <form method="POST" action="">
            <div class="field-group">
                <label for="username">Username</label>
                <i class="fa-solid fa-user"></i>
                <input type="text" id="username" name="username" placeholder="Enter your username" required>
            </div>
            <div class="field-group">
                <label for="password">Password</label>
                <i class="fa-solid fa-lock"></i>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit"><i class="fa-solid fa-arrow-right-to-bracket"></i> Log In</button>
        </form>
        <p>Don't have an account? <a href="register.php">Registration</a></p>
        <hr>
        <div class="security-info">
            <i class="fa-solid fa-lock"></i> This application uses advanced encryption to protect your personal information
        </div>
    </div>
</body>
</html>