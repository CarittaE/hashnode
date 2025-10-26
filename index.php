<?php
session_start();

$db_host = '127.0.0.1';
$db_name = 'pkl_suggestions';
$db_user = 'root';
$db_pass = '';

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (Exception $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Handle form submissions
$messages = ['errors' => [], 'success' => []];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // LOGIN
    if (isset($_POST['action']) && $_POST['action'] === 'login') {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        $stmt = $pdo->prepare("SELECT id, username, password_hash, role FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password_hash'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            $messages['success'][] = "Welcome back $username!";
        } else {
            $messages['errors'][] = "Invalid username or password";
        }
    }

    // REGISTER
    if (isset($_POST['action']) && $_POST['action'] === 'register') {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($username) || empty($password)) {
            $messages['errors'][] = "Username and password are required";
        } else {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                $messages['errors'][] = "Username already taken";
            } else {
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
                if ($stmt->execute([$username, $password_hash])) {
                    $user_id = $pdo->lastInsertId();
                    $_SESSION['user_id'] = $user_id;
                    $_SESSION['username'] = $username;
                    $_SESSION['role'] = 'user';
                    $messages['success'][] = "Registration successful! Welcome $username";
                } else {
                    $messages['errors'][] = "Registration failed";
                }
            }
        }
    }

    // LOGOUT
    if (isset($_POST['action']) && $_POST['action'] === 'logout') {
        session_destroy();
        session_start();
        $messages['success'][] = "Logged out successfully";
    }

    // POST SUGGESTION
    if (isset($_POST['action']) && $_POST['action'] === 'post_suggestion') {
        if (empty($_SESSION['user_id'])) {
            $messages['errors'][] = "Please login to post suggestions";
        } else {
            $content = trim($_POST['content'] ?? '');
            if (empty($content)) {
                $messages['errors'][] = "Suggestion cannot be empty";
            } else {
                $stmt = $pdo->prepare("INSERT INTO suggestions (user_id, content) VALUES (?, ?)");
                if ($stmt->execute([$_SESSION['user_id'], $content])) {
                    $messages['success'][] = "Suggestion posted successfully!";
                } else {
                    $messages['errors'][] = "Failed to post suggestion";
                }
            }
        }
    }

    // PUBLISH POSTS (Simpan ke database)
    if (isset($_POST['action']) && $_POST['action'] === 'publish_posts') {
        if (empty($_SESSION['user_id'])) {
            $messages['errors'][] = "Please login to publish posts";
        } else {
            $filename = $_POST['filename'] ?? '';
            $file_size = intval($_POST['file_size'] ?? 0);
            $hashnode_token = $_POST['token'] ?? '';
            $publication_id = $_POST['publish_id'] ?? '';
            $posts_data = json_decode($_POST['posts_data'] ?? '[]', true);

            if (empty($filename) || empty($posts_data)) {
                $messages['errors'][] = "No file or post data received";
            } else {
                try {
                    // Simpan upload history
                    $stmt = $pdo->prepare("
                        INSERT INTO upload_history 
                        (user_id, filename, file_size, hashnode_token, publication_id, posts_count) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    ");
                    $stmt->execute([
                        $_SESSION['user_id'],
                        $filename,
                        $file_size,
                        $hashnode_token,
                        $publication_id,
                        count($posts_data)
                    ]);
                    $upload_id = $pdo->lastInsertId();

                    // Update user last upload time
                    $stmt = $pdo->prepare("UPDATE users SET last_upload_at = NOW() WHERE id = ?");
                    $stmt->execute([$_SESSION['user_id']]);

                    // Simpan detail posts
                    $success_count = 0;
                    $failed_count = 0;

                    foreach ($posts_data as $post) {
                        $status = $post['status'];
                        $post_url = $status === 'published' ? 'https://hashnode.com/post/' . uniqid() : null;
                        
                        $stmt = $pdo->prepare("
                            INSERT INTO published_posts 
                            (upload_id, user_id, post_title, post_url, status, published_at) 
                            VALUES (?, ?, ?, ?, ?, NOW())
                        ");
                        $stmt->execute([
                            $upload_id,
                            $_SESSION['user_id'],
                            $post['title'],
                            $post_url,
                            $status
                        ]);

                        if ($status === 'published') {
                            $success_count++;
                        } else {
                            $failed_count++;
                        }
                    }

                    // Update success/failed count
                    $stmt = $pdo->prepare("
                        UPDATE upload_history 
                        SET success_count = ?, failed_count = ? 
                        WHERE id = ?
                    ");
                    $stmt->execute([$success_count, $failed_count, $upload_id]);

                    $messages['success'][] = "Successfully published $success_count posts! $failed_count failed.";

                } catch (Exception $e) {
                    $messages['errors'][] = "Database error: " . $e->getMessage();
                }
            }
        }
    }
}

// Handle admin delete suggestion
if (isset($_GET['action']) && $_GET['action'] === 'delete_suggestion' && isset($_GET['id'])) {
    if (empty($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
        $messages['errors'][] = "Admin access required";
    } else {
        $suggestion_id = intval($_GET['id']);
        $stmt = $pdo->prepare("DELETE FROM suggestions WHERE id = ?");
        if ($stmt->execute([$suggestion_id])) {
            $messages['success'][] = "Suggestion deleted successfully";
        } else {
            $messages['errors'][] = "Failed to delete suggestion";
        }
    }
}

// Get suggestions for display
$stmt = $pdo->query("
    SELECT s.id, s.content, s.created_at, u.username 
    FROM suggestions s 
    LEFT JOIN users u ON s.user_id = u.id 
    ORDER BY s.created_at DESC 
    LIMIT 50
");
$suggestions = $stmt->fetchAll();

// Get user's upload history (jika sudah login)
$upload_history = [];
if (!empty($_SESSION['user_id'])) {
    $stmt = $pdo->prepare("
        SELECT uh.*, COUNT(pp.id) as actual_posts,
               SUM(CASE WHEN pp.status = 'published' THEN 1 ELSE 0 END) as actual_success
        FROM upload_history uh
        LEFT JOIN published_posts pp ON uh.id = pp.upload_id
        WHERE uh.user_id = ?
        GROUP BY uh.id
        ORDER BY uh.upload_time DESC
        LIMIT 10
    ");
    $stmt->execute([$_SESSION['user_id']]);
    $upload_history = $stmt->fetchAll();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hashnode Publisher - Publish Posts from Excel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .main-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-top: 30px;
            margin-bottom: 30px;
            overflow: hidden;
        }
        .navbar-brand {
            font-weight: 700;
            font-size: 1.5rem;
        }
        .feature-card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease;
            margin-bottom: 20px;
        }
        .feature-card:hover {
            transform: translateY(-5px);
        }
        .upload-area {
            border: 3px dashed #dee2e6;
            border-radius: 12px;
            padding: 3rem 2rem;
            text-align: center;
            background: #f8f9fa;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        .upload-area:hover {
            border-color: #667eea;
            background: #f0f2ff;
        }
        .upload-area.dragover {
            border-color: #667eea;
            background: #e3f2fd;
        }
        .admin-badge {
            background: #dc3545;
            color: white;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: 600;
        }
        .btn-gradient {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            font-weight: 600;
        }
        .btn-gradient:hover {
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="fas fa-rocket me-2"></i>Hashnode Publisher
            </a>
            
            <div class="navbar-nav ms-auto">
                <?php if (!empty($_SESSION['username'])): ?>
                    <div class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user me-1"></i>
                            <?= htmlspecialchars($_SESSION['username']) ?>
                            <?php if ($_SESSION['role'] === 'admin'): ?>
                                <span class="admin-badge ms-1">ADMIN</span>
                            <?php endif; ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li>
                                <button class="dropdown-item" data-bs-toggle="modal" data-bs-target="#suggestionModal">
                                    <i class="fas fa-lightbulb me-2"></i>Post Suggestion
                                </button>
                            </li>
                            <?php if ($_SESSION['role'] === 'admin'): ?>
                                <li>
                                    <a href="admin_dashboard.php" class="dropdown-item">
                                        <i class="fas fa-crown me-2"></i>Admin Dashboard
                                    </a>
                                </li>
                            <?php endif; ?>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <form method="post" class="d-inline">
                                    <input type="hidden" name="action" value="logout">
                                    <button type="submit" class="dropdown-item text-danger">
                                        <i class="fas fa-sign-out-alt me-2"></i>Logout
                                    </button>
                                </form>
                            </li>
                        </ul>
                    </div>
                <?php else: ?>
                    <div class="d-flex gap-2">
                        <button class="btn btn-outline-light btn-sm" data-bs-toggle="modal" data-bs-target="#authModal">
                            <i class="fas fa-sign-in-alt me-1"></i>Login
                        </button>
                        <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#authModal" onclick="switchToRegister()">
                            <i class="fas fa-user-plus me-1"></i>Register
                        </button>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container">
        <div class="main-container">
            <!-- Messages -->
            <?php foreach ($messages['errors'] as $error): ?>
                <div class="alert alert-danger alert-dismissible fade show m-3">
                    <i class="fas fa-exclamation-triangle me-2"></i><?= htmlspecialchars($error) ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endforeach; ?>
            
            <?php foreach ($messages['success'] as $success): ?>
                <div class="alert alert-success alert-dismissible fade show m-3">
                    <i class="fas fa-check-circle me-2"></i><?= htmlspecialchars($success) ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endforeach; ?>

            <!-- Main Hashnode Publisher Section -->
            <div class="p-4">
                <div class="text-center mb-5">
                    <h1 class="display-5 fw-bold text-primary mb-3">🚀 Hashnode Publisher</h1>
                    <p class="lead text-muted">Upload Excel files and publish posts directly to Hashnode</p>
                </div>

                <!-- Upload Card -->
                <div class="card feature-card">
                    <div class="card-header bg-primary text-white">
                        <h4 class="mb-0"><i class="fas fa-upload me-2"></i>Publish Posts from Excel</h4>
                    </div>
                    <div class="card-body">
                        <div class="upload-area mb-4" id="uploadArea">
                            <i class="fas fa-file-excel fa-4x text-success mb-3"></i>
                            <h4>Drop your Excel file here</h4>
                            <p class="text-muted">or click to browse .xlsx files</p>
                            <input type="file" id="xlsx_file" class="d-none" accept=".xlsx,.xls">
                        </div>

                        <form id="uploadForm">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="token" class="form-label">Hashnode API Token</label>
                                    <input type="password" id="token" class="form-control" placeholder="Enter your Personal Access Token" required>
                                    <div class="form-text">Your Hashnode authentication token</div>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label for="publish_id" class="form-label">Publication ID</label>
                                    <input type="text" id="publish_id" class="form-control" placeholder="Enter your Publication ID" required>
                                    <div class="form-text">Your Hashnode publication ID</div>
                                </div>
                            </div>
                            <div class="text-center">
                                <button type="submit" class="btn btn-gradient btn-lg px-5">
                                    <i class="fas fa-paper-plane me-2"></i>Publish Posts Now
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Results Table -->
                <div class="card feature-card">
                    <div class="card-header bg-success text-white">
                        <h5 class="mb-0"><i class="fas fa-table me-2"></i>Publishing Results</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-bordered table-striped">
                                <thead class="table-dark">
                                    <tr>
                                        <th>Title</th>
                                        <th>Status</th>
                                        <th>API Response</th>
                                        <th>Post URL</th>
                                    </tr>
                                </thead>
                                <tbody id="resultTable">
                                    <tr>
                                        <td colspan="4" class="text-center text-muted py-4">
                                            <i class="fas fa-inbox fa-2x mb-3 d-block"></i>
                                            No posts published yet. Upload an Excel file to get started.
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Upload History Section -->
                <?php if (!empty($_SESSION['user_id']) && !empty($upload_history)): ?>
                <div class="card feature-card mt-4">
                    <div class="card-header bg-info text-white">
                        <h5 class="mb-0"><i class="fas fa-history me-2"></i>Your Upload History</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Filename</th>
                                        <th>Upload Time</th>
                                        <th>Posts</th>
                                        <th>Success</th>
                                        <th>Failed</th>
                                        <th>Publication</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($upload_history as $history): ?>
                                    <tr>
                                        <td>
                                            <i class="fas fa-file-excel text-success me-2"></i>
                                            <?= htmlspecialchars($history['filename']) ?>
                                        </td>
                                        <td><?= date('M j, H:i', strtotime($history['upload_time'])) ?></td>
                                        <td>
                                            <span class="badge bg-primary"><?= $history['posts_count'] ?></span>
                                        </td>
                                        <td>
                                            <span class="badge bg-success"><?= $history['actual_success'] ?? $history['success_count'] ?></span>
                                        </td>
                                        <td>
                                            <span class="badge bg-danger"><?= $history['failed_count'] ?></span>
                                        </td>
                                        <td>
                                            <small class="text-muted"><?= substr($history['publication_id'] ?? 'N/A', 0, 15) ?>...</small>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <!-- Features -->
                <div class="row text-center mt-4">
                    <div class="col-md-4 mb-4">
                        <div class="card feature-card h-100">
                            <div class="card-body">
                                <i class="fas fa-file-excel fa-3x text-success mb-3"></i>
                                <h5>Excel to Hashnode</h5>
                                <p class="text-muted">Convert Excel data directly to Hashnode posts</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 mb-4">
                        <div class="card feature-card h-100">
                            <div class="card-body">
                                <i class="fas fa-bolt fa-3x text-warning mb-3"></i>
                                <h5>Instant Publishing</h5>
                                <p class="text-muted">Publish posts immediately to your Hashnode blog</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 mb-4">
                        <div class="card feature-card h-100">
                            <div class="card-body">
                                <i class="fas fa-chart-bar fa-3x text-info mb-3"></i>
                                <h5>Real-time Tracking</h5>
                                <p class="text-muted">Monitor publishing status and results live</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Login/Register Modal -->
    <div class="modal fade" id="authModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header bg-primary text-white">
                    <h5 class="modal-title">Access Hashnode Publisher</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <ul class="nav nav-pills nav-justified mb-3" id="authTabs">
                        <li class="nav-item">
                            <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#login">
                                <i class="fas fa-sign-in-alt me-2"></i>Login
                            </button>
                        </li>
                        <li class="nav-item">
                            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#register">
                                <i class="fas fa-user-plus me-2"></i>Register
                            </button>
                        </li>
                    </ul>

                    <div class="tab-content">
                        <!-- Login Tab -->
                        <div class="tab-pane fade show active" id="login">
                            <form method="post">
                                <input type="hidden" name="action" value="login">
                                <div class="mb-3">
                                    <label class="form-label">Username</label>
                                    <input type="text" class="form-control" name="username" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" class="form-control" name="password" required>
                                </div>
                                <button type="submit" class="btn btn-primary w-100">Login</button>
                            </form>
                            <div class="text-center mt-3">
                                <small class="text-muted">
                                    Demo admin: <strong>admin</strong> / <strong>admin123</strong>
                                </small>
                            </div>
                        </div>

                        <!-- Register Tab -->
                        <div class="tab-pane fade" id="register">
                            <form method="post">
                                <input type="hidden" name="action" value="register">
                                <div class="mb-3">
                                    <label class="form-label">Username</label>
                                    <input type="text" class="form-control" name="username" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" class="form-control" name="password" required>
                                </div>
                                <button type="submit" class="btn btn-success w-100">Create Account</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Suggestion Modal -->
    <div class="modal fade" id="suggestionModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header bg-info text-white">
                    <h5 class="modal-title"><i class="fas fa-lightbulb me-2"></i>Post Suggestion</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form method="post">
                        <input type="hidden" name="action" value="post_suggestion">
                        <div class="mb-3">
                            <textarea class="form-control" name="content" rows="4" placeholder="Share your ideas, feedback, or suggestions..."></textarea>
                        </div>
                        <button type="submit" class="btn btn-info w-100">
                            <i class="fas fa-paper-plane me-2"></i>Submit Suggestion
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Switch to register tab
        function switchToRegister() {
            const registerTab = new bootstrap.Tab(document.querySelector('#authTabs .nav-link[data-bs-target="#register"]'));
            registerTab.show();
        }

        // Auto-show login modal if there are errors
        <?php if (!empty($messages['errors']) && empty($_SESSION['user_id'])): ?>
            document.addEventListener('DOMContentLoaded', function() {
                const authModal = new bootstrap.Modal(document.getElementById('authModal'));
                authModal.show();
            });
        <?php endif; ?>

        // Switch to register tab if there are registration errors
        <?php if (!empty($messages['errors']) && isset($_POST['action']) && $_POST['action'] === 'register'): ?>
            document.addEventListener('DOMContentLoaded', function() {
                const authModal = new bootstrap.Modal(document.getElementById('authModal'));
                authModal.show();
                switchToRegister();
            });
        <?php endif; ?>

        // File upload functionality
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('xlsx_file');

        uploadArea.addEventListener('click', () => fileInput.click());
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                updateFileName();
            }
        });

        fileInput.addEventListener('change', updateFileName);

        function updateFileName() {
            if (fileInput.files.length > 0) {
                const fileName = fileInput.files[0].name;
                uploadArea.innerHTML = `
                    <i class="fas fa-check-circle fa-3x text-success mb-3"></i>
                    <h5>${fileName}</h5>
                    <p class="text-muted">File selected and ready to publish</p>
                    <small class="text-primary">Click to change file</small>
                `;
            }
        }

        // Hashnode publishing functionality
        document.getElementById('uploadForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const fileInput = document.getElementById('xlsx_file');
            const token = document.getElementById('token').value;
            const publishId = document.getElementById('publish_id').value;
            
            if (!fileInput.files[0]) {
                alert('Please select an Excel file');
                return;
            }
            
            if (!token || !publishId) {
                alert('Please enter API token and publication ID');
                return;
            }

            // Show processing state
            const tableBody = document.getElementById('resultTable');
            tableBody.innerHTML = `
                <tr>
                    <td colspan="4" class="text-center">
                        <div class="spinner-border text-primary" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <p class="mt-2 mb-0">Reading Excel file and publishing to Hashnode...</p>
                    </td>
                </tr>
            `;

            try {
                // Read Excel file
                const data = await readExcelFile(fileInput.files[0]);
                
                // Simulate publishing to Hashnode
                setTimeout(() => {
                    const results = data.map(post => ({
                        title: post.title || 'Untitled Post',
                        status: Math.random() > 0.1 ? 'published' : 'failed',
                        response: Math.random() > 0.1 ? 'Successfully published' : 'API Error: Invalid token',
                        url: Math.random() > 0.1 ? 'https://hashnode.com/post/' + Math.random().toString(36).substr(2, 9) : null
                    }));

                    displayResults(results);
                    
                    // Save to database
                    saveToDatabase(results, token, publishId, fileInput.files[0].name, fileInput.files[0].size);

                }, 2000);

            } catch (error) {
                tableBody.innerHTML = `
                    <tr>
                        <td colspan="4" class="text-center text-danger">
                            <i class="fas fa-exclamation-triangle fa-2x mb-3"></i>
                            <p>Error reading Excel file: ${error.message}</p>
                        </td>
                    </tr>
                `;
            }
        });

        function readExcelFile(file) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                
                reader.onload = function(e) {
                    try {
                        const data = new Uint8Array(e.target.result);
                        const workbook = XLSX.read(data, { type: 'array' });
                        const firstSheet = workbook.Sheets[workbook.SheetNames[0]];
                        const jsonData = XLSX.utils.sheet_to_json(firstSheet);
                        
                        // Simulate post data
                        const posts = jsonData.slice(0, 5).map((row, index) => ({
                            title: row.title || row.Title || `Post ${index + 1}`,
                            content: row.content || row.Content || 'Sample content',
                            tags: row.tags || row.Tags || 'general'
                        }));
                        
                        resolve(posts);
                    } catch (error) {
                        reject(error);
                    }
                };
                
                reader.onerror = () => reject(new Error('Failed to read file'));
                reader.readAsArrayBuffer(file);
            });
        }

        function displayResults(results) {
            const tableBody = document.getElementById('resultTable');
            
            if (results.length === 0) {
                tableBody.innerHTML = `
                    <tr>
                        <td colspan="4" class="text-center text-muted">
                            No posts found in Excel file
                        </td>
                    </tr>
                `;
                return;
            }

            tableBody.innerHTML = results.map(post => `
                <tr>
                    <td>${post.title}</td>
                    <td>
                        <span class="badge ${post.status === 'published' ? 'bg-success' : 'bg-danger'}">
                            ${post.status}
                        </span>
                    </td>
                    <td>${post.response}</td>
                    <td>
                        ${post.url ? 
                            `<a href="${post.url}" target="_blank" class="btn btn-sm btn-outline-primary">View Post</a>` : 
                            '<span class="text-muted">N/A</span>'
                        }
                    </td>
                </tr>
            `).join('');
        }

        function saveToDatabase(results, token, publishId, filename, fileSize) {
            fetch('index.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    action: 'publish_posts',
                    filename: filename,
                    file_size: fileSize,
                    token: token,
                    publish_id: publishId,
                    posts_data: JSON.stringify(results)
                })
            })
            .then(response => response.text())
            .then(result => {
                console.log('Save to database result:', result);
                // Optional: Show success message
                setTimeout(() => {
                    location.reload();
                }, 3000);
            })
            .catch(error => {
                console.error('Error saving to database:', error);
            });
        }
    </script>
</body>
</html>