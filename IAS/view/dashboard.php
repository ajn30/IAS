<?php
session_start();
require_once __DIR__ . '/../security/homomorphic/homomorphic_key_management.php';
require_once __DIR__ . '/../security/homomorphic/paillier_encryption.php';
require_once __DIR__ . '/../config/database.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

// Initialize variables
$salaryCalculation = '';
$error = '';
$keyManager = null;
$paillier = null;
$keys = null;

// Only initialize encryption if form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['calculate_salary'])) {
    try {
        // Initialize encryption only when needed
        $keyManager = HomomorphicKeyManagement::getInstance();
        $paillier = new PaillierEncryption();
        $keys = $keyManager->getPaillierKeys($_SESSION['user_id']);
        
        // Validate inputs
        $baseSalary = filter_input(INPUT_POST, 'base_salary', FILTER_VALIDATE_INT);
        $bonus = filter_input(INPUT_POST, 'bonus', FILTER_VALIDATE_INT);
        $taxRate = filter_input(INPUT_POST, 'tax_rate', FILTER_VALIDATE_FLOAT);
        
        if ($baseSalary === false || $bonus === false || $taxRate === false) {
            throw new Exception("Please enter valid numbers");
        }
        
        // Encrypt values
        $encryptedBase = $paillier->encrypt($baseSalary, $keys['public']);
        $encryptedBonus = $paillier->encrypt($bonus, $keys['public']);
        
        // Perform homomorphic addition for gross salary
        $encryptedGross = $paillier->addEncrypted($encryptedBase, $encryptedBonus, $keys['public']);
        
        // Decrypt the result
        $grossSalary = $paillier->decrypt($encryptedGross, $keys['private'], $keys['public']);
        
        // Calculate tax
        $netSalary = $grossSalary * (1 - ($taxRate / 100));
        
        // Format the results
        $salaryCalculation = sprintf(
            "Base Salary: $%s\nBonus: $%s\nGross Salary: $%s\nTax Rate: %.1f%%\nNet Salary: $%.2f",
            number_format($baseSalary),
            number_format($bonus),
            number_format($grossSalary),
            $taxRate,
            $netSalary
        );
        
        // Store in database using the existing PDO connection
        try {
            global $pdo;
            $stmt = $pdo->prepare("INSERT INTO salary_data (user_id, base_salary, bonus, tax_rate, encrypted_total) 
                                  VALUES (?, ?, ?, ?, ?)");
            $stmt->execute([
                $_SESSION['user_id'],
                $encryptedBase,
                $encryptedBonus,
                $taxRate,
                $encryptedGross
            ]);
        } catch (PDOException $e) {
            error_log($e->getMessage());
            throw new Exception("Failed to save calculation results");
        }
        
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link rel="stylesheet" href="app/dashboard.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* Sidebar styles */
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 220px;
            height: 100vh;
            background: #2c3e50;
            color: #fff;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding-top: 40px;
            z-index: 10;
        }
        .sidebar .avatar {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: #fff;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            color: #2c3e50;
        }
        .sidebar nav {
            width: 100%;
        }
        .sidebar nav a {
            display: flex;
            align-items: center;
            padding: 15px 30px;
            color: #fff;
            text-decoration: none;
            font-size: 1.1rem;
            transition: background 0.2s;
        }
        .sidebar nav a i {
            margin-right: 12px;
            font-size: 1.2rem;
        }
        .sidebar nav a.active, .sidebar nav a:hover {
            background: #34495e;
        }
        @media (max-width: 900px) {
            .sidebar {
                position: static;
                width: 100%;
                height: auto;
                flex-direction: row;
                padding: 10px 0;
            }
            .sidebar .avatar {
                width: 50px;
                height: 50px;
                font-size: 1.5rem;
                margin-bottom: 0;
                margin-right: 20px;
            }
            .sidebar nav {
                display: flex;
                flex-direction: row;
                width: auto;
            }
            .sidebar nav a {
                padding: 10px 15px;
                font-size: 1rem;
            }
        }
        .main-content {
            margin-left: 240px;
            padding: 40px 20px;
            min-height: 100vh;
            background: #f5f7fa;
            transition: margin 0.3s;
        }
        @media (max-width: 900px) {
            .main-content {
                margin-left: 0;
                padding: 20px 5px;
            }
        }
        .dashboard-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 30px;
        }
        .dashboard-header h1 {
            margin: 0;
            font-size: 2rem;
            color: #2c3e50;
            border: none;
            padding: 0;
        }
        .dashboard-header .logout {
            margin-left: 20px;
        }
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }
        @media (max-width: 900px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
                gap: 20px;
            }
        }
        .info-label i {
            margin-right: 8px;
            color: #2980b9;
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="avatar">
            <i class="fa-solid fa-user"></i>
        </div>
        <nav>
            <a href="#" class="active"><i class="fa-solid fa-gauge"></i>Dashboard</a>
            <a href="logout.php"><i class="fa-solid fa-right-from-bracket"></i>Logout</a>
        </nav>
    </div>
    <div class="main-content">
        <div class="dashboard-header">
            <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></h1>
            <a href="logout.php" class="logout">Logout</a>
        </div>
        <div class="dashboard-grid">
            <!-- User Information Card -->
            <div class="card user-info-card">
                <h2><i class="fa-solid fa-id-card"></i> Personal Information</h2>
                <div class="user-info">
                    <div class="info-item">
                        <div class="info-label"><i class="fa-solid fa-user"></i>Name:</div>
                        <div class="info-value"><?php echo isset($_SESSION['name']) ? htmlspecialchars($_SESSION['name']) : 'Not set'; ?></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label"><i class="fa-solid fa-envelope"></i>Email:</div>
                        <div class="info-value"><?php echo isset($_SESSION['email']) ? htmlspecialchars($_SESSION['email']) : 'Not set'; ?></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label"><i class="fa-solid fa-phone"></i>Phone Number:</div>
                        <div class="info-value"><?php echo isset($_SESSION['phone_number']) ? htmlspecialchars($_SESSION['phone_number']) : 'Not set'; ?></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label"><i class="fa-solid fa-location-dot"></i>Address:</div>
                        <div class="info-value"><?php echo isset($_SESSION['address']) ? htmlspecialchars($_SESSION['address']) : 'Not set'; ?></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label"><i class="fa-solid fa-id-badge"></i>Credit card Number:</div>
                        <div class="info-value"><?php echo isset($_SESSION['social_security_number']) ? htmlspecialchars($_SESSION['social_security_number']) : 'Not set'; ?></div>
                    </div>
                </div>
            </div>
            <!-- Credit card Calculator -->
            <div class="Credit-card-calculator">
                <h2><i class="fa-solid fa-calculator"></i> Credit card Calculator</h2>
                <?php if ($error): ?>
                    <div class="error"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>
                <form method="POST" action="">
                    <div class="form-group">
                        <label for="base_salary"><i class="fa-solid fa-money-bill-wave"></i> Base Salary ($):</label>
                        <input type="number" id="base_salary" name="base_salary" min="0" required>
                    </div>
                    <div class="form-group">
                        <label for="bonus"><i class="fa-solid fa-gift"></i> Christmas Bonus ($):</label>
                        <input type="number" id="bonus" name="bonus" min="0" required>
                    </div>
                    <div class="form-group">
                        <label for="tax_rate"><i class="fa-solid fa-percent"></i> Tax percent Rate (%):</label>
                        <input type="number" id="tax_rate" name="tax_rate" step="0.1" min="0" max="100" required>
                    </div>
                    <button type="submit" name="calculate_salary"><i class="fa-solid fa-equals"></i> Calculate Salary</button>
                </form>
                <?php if ($salaryCalculation): ?>
                <table class="calculation-table">
                    <tr>
                        <th>Component</th>
                        <th>Amount</th>
                    </tr>
                    <tr>
                        <td>Salary</td>
                        <td class="amount">$<?php echo number_format($baseSalary); ?></td>
                    </tr>
                    <tr>
                        <td>Bonus</td>
                        <td class="amount">$<?php echo number_format($bonus); ?></td>
                    </tr>
                    <tr>
                        <td>Gross Salary</td>
                        <td class="amount">$<?php echo number_format($grossSalary); ?></td>
                    </tr>
                    <tr>
                        <td>Tax Rate</td>
                        <td class="amount"><?php echo number_format($taxRate, 1); ?>%</td>
                    </tr>
                    <tr class="highlight">
                        <td>Net Salary</td>
                        <td class="amount">$<?php echo number_format($netSalary, 2); ?></td>
                    </tr>
                </table>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>