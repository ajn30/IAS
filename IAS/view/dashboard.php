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
</head>
<body>
    <div class="container">
        <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></h1>
        
        <!-- User Information -->
        <div class="card user-info-card">
            <h2>Personal Information</h2>
            <div class="user-info">
                <div class="info-item">
                    <div class="info-label">Name:</div>
                    <div class="info-value"><?php echo isset($_SESSION['name']) ? htmlspecialchars($_SESSION['name']) : 'Not set'; ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Email:</div>
                    <div class="info-value"><?php echo isset($_SESSION['email']) ? htmlspecialchars($_SESSION['email']) : 'Not set'; ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Phone Number:</div>
                    <div class="info-value"><?php echo isset($_SESSION['phone_number']) ? htmlspecialchars($_SESSION['phone_number']) : 'Not set'; ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Address:</div>
                    <div class="info-value"><?php echo isset($_SESSION['address']) ? htmlspecialchars($_SESSION['address']) : 'Not set'; ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Social Security Number:</div>
                    <div class="info-value"><?php echo isset($_SESSION['social_security_number']) ? htmlspecialchars($_SESSION['social_security_number']) : 'Not set'; ?></div>
                </div>
            </div>
        </div>

        <!-- Salary Calculator -->
        <div class="card">
            <h2>Salary Calculator</h2>
            
            <?php if ($error): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <form method="POST" action="">
                <div class="form-group">
                    <label for="base_salary">Base Salary ($):</label>
                    <input type="number" id="base_salary" name="base_salary" min="0" required>
                </div>
                
                <div class="form-group">
                    <label for="bonus">Bonus ($):</label>
                    <input type="number" id="bonus" name="bonus" min="0" required>
                </div>
                
                <div class="form-group">
                    <label for="tax_rate">Tax Rate (%):</label>
                    <input type="number" id="tax_rate" name="tax_rate" step="0.1" min="0" max="100" required>
                </div>
                
                <button type="submit" name="calculate_salary">Calculate Salary</button>
            </form>
            
            <?php if ($salaryCalculation): ?>
            <table class="calculation-table">
                <tr>
                    <th>Component</th>
                    <th>Amount</th>
                </tr>
                <tr>
                    <td>Base Salary</td>
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

        <a href="logout.php" class="logout">Logout</a>
    </div>
</body>
</html>