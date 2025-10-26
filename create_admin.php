<?php
// File untuk create admin user dengan password yang benar
$db_host = '127.0.0.1';
$db_name = 'pkl_suggestions';
$db_user = 'root';
$db_pass = '';

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
} catch (Exception $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Password yang ingin kita gunakan
$password = 'admin123';
$password_hash = password_hash($password, PASSWORD_DEFAULT);

// Cek apakah admin sudah ada
$stmt = $pdo->prepare("SELECT id FROM users WHERE username = 'admin'");
$stmt->execute();
$admin_exists = $stmt->fetch();

if ($admin_exists) {
    // Update password admin yang sudah ada
    $stmt = $pdo->prepare("UPDATE users SET password_hash = ? WHERE username = 'admin'");
    $stmt->execute([$password_hash]);
    echo "✅ Admin password updated successfully!<br>";
    echo "Password: admin123<br>";
    echo "Hash: " . $password_hash . "<br>";
} else {
    // Buat admin baru
    $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, role) VALUES ('admin', ?, 'admin')");
    $stmt->execute([$password_hash]);
    echo "✅ Admin user created successfully!<br>";
    echo "Username: admin<br>";
    echo "Password: admin123<br>";
    echo "Hash: " . $password_hash . "<br>";
}

echo "<br><a href='index.php'>Go to Main Page</a>";
?>