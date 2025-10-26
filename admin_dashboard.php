<?php
session_start();
if (empty($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit;
}

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

// Handle delete suggestion
if (isset($_GET['action']) && $_GET['action'] === 'delete_suggestion' && isset($_GET['id'])) {
    $suggestion_id = intval($_GET['id']);
    $stmt = $pdo->prepare("DELETE FROM suggestions WHERE id = ?");
    $stmt->execute([$suggestion_id]);
    header('Location: admin_dashboard.php?deleted=1');
    exit;
}

// Get statistics
$users_count = $pdo->query("SELECT COUNT(*) as count FROM users")->fetch()['count'];
$suggestions_count = $pdo->query("SELECT COUNT(*) as count FROM suggestions")->fetch()['count'];
$admins_count = $pdo->query("SELECT COUNT(*) as count FROM users WHERE role = 'admin'")->fetch()['count'];
$total_uploads = $pdo->query("SELECT COUNT(*) as count FROM upload_history")->fetch()['count'];
$total_published_posts = $pdo->query("SELECT COUNT(*) as count FROM published_posts WHERE status = 'published'")->fetch()['count'];

// Get recent uploads
$recent_uploads = $pdo->query("
    SELECT uh.*, u.username 
    FROM upload_history uh 
    LEFT JOIN users u ON uh.user_id = u.id 
    ORDER BY uh.upload_time DESC 
    LIMIT 10
")->fetchAll();

// Get all suggestions with user info
$stmt = $pdo->query("
    SELECT s.id, s.content, s.created_at, u.username, u.role 
    FROM suggestions s 
    LEFT JOIN users u ON s.user_id = u.id 
    ORDER BY s.created_at DESC
");
$suggestions = $stmt->fetchAll();

// Get all users
$users = $pdo->query("SELECT id, username, role, created_at, last_upload_at FROM users ORDER BY created_at DESC")->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Hashnode Publisher</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .sidebar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            min-height: 100vh;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .sidebar .nav-link {
            color: white;
            padding: 12px 20px;
            margin: 5px 0;
            border-radius: 8px;
            transition: all 0.3s ease;
        }
        .sidebar .nav-link:hover, .sidebar .nav-link.active {
            background: rgba(255,255,255,0.2);
            transform: translateX(5px);
        }
        .stat-card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .main-content {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 sidebar p-0">
                <div class="p-4">
                    <h4 class="text-white mb-4">
                        <i class="fas fa-crown me-2"></i>Admin Dashboard
                    </h4>
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link active" href="admin_dashboard.php">
                                <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#suggestions" data-bs-toggle="tab">
                                <i class="fas fa-lightbulb me-2"></i>Suggestions
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#users" data-bs-toggle="tab">
                                <i class="fas fa-users me-2"></i>Users
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#uploads" data-bs-toggle="tab">
                                <i class="fas fa-upload me-2"></i>Uploads
                            </a>
                        </li>
                        <li class="nav-item mt-4">
                            <a class="nav-link" href="index.php">
                                <i class="fas fa-arrow-left me-2"></i>Back to Main
                            </a>
                        </li>
                    </ul>
                </div>
            </div>

            <!-- Main Content -->
            <div class="col-md-9 col-lg-10 ml-sm-auto p-4">
                <?php if (isset($_GET['deleted'])): ?>
                    <div class="alert alert-success alert-dismissible fade show">
                        <i class="fas fa-check-circle me-2"></i>Suggestion deleted successfully!
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>

                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2 class="h3 mb-0">Welcome, <?= htmlspecialchars($_SESSION['username']) ?>!</h2>
                    <span class="badge bg-danger fs-6">Administrator</span>
                </div>

                <!-- Statistics Cards -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card stat-card text-white bg-primary">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <h4 class="card-title"><?= $users_count ?></h4>
                                        <p class="card-text">Total Users</p>
                                    </div>
                                    <i class="fas fa-users fa-2x opacity-50"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stat-card text-white bg-success">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <h4 class="card-title"><?= $suggestions_count ?></h4>
                                        <p class="card-text">Total Suggestions</p>
                                    </div>
                                    <i class="fas fa-lightbulb fa-2x opacity-50"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stat-card text-white bg-info">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <h4 class="card-title"><?= $total_uploads ?></h4>
                                        <p class="card-text">Total Uploads</p>
                                    </div>
                                    <i class="fas fa-upload fa-2x opacity-50"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stat-card text-white bg-warning">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <h4 class="card-title"><?= $total_published_posts ?></h4>
                                        <p class="card-text">Published Posts</p>
                                    </div>
                                    <i class="fas fa-paper-plane fa-2x opacity-50"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Tab Content -->
                <div class="tab-content">
                    <!-- Dashboard Tab -->
                    <div class="tab-pane fade show active" id="dashboard">
                        <div class="main-content">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0"><i class="fas fa-chart-line me-2"></i>Recent Upload Activity</h5>
                            </div>
                            <div class="card-body">
                                <?php if (empty($recent_uploads)): ?>
                                    <p class="text-muted text-center py-4">No upload activity yet.</p>
                                <?php else: ?>
                                    <div class="table-responsive">
                                        <table class="table table-striped">
                                            <thead>
                                                <tr>
                                                    <th>User</th>
                                                    <th>Filename</th>
                                                    <th>Upload Time</th>
                                                    <th>Posts</th>
                                                    <th>Success</th>
                                                    <th>Failed</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($recent_uploads as $upload): ?>
                                                <tr>
                                                    <td>
                                                        <strong><?= htmlspecialchars($upload['username']) ?></strong>
                                                        <?php if ($upload['username'] === 'admin'): ?>
                                                            <span class="badge bg-danger ms-1">ADMIN</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td><?= htmlspecialchars($upload['filename']) ?></td>
                                                    <td><?= date('M j, H:i', strtotime($upload['upload_time'])) ?></td>
                                                    <td>
                                                        <span class="badge bg-primary"><?= $upload['posts_count'] ?></span>
                                                    </td>
                                                    <td>
                                                        <span class="badge bg-success"><?= $upload['success_count'] ?></span>
                                                    </td>
                                                    <td>
                                                        <span class="badge bg-danger"><?= $upload['failed_count'] ?></span>
                                                    </td>
                                                </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <!-- Suggestions Tab -->
                    <div class="tab-pane fade" id="suggestions">
                        <div class="main-content">
                            <div class="card-header bg-info text-white">
                                <h5 class="mb-0"><i class="fas fa-lightbulb me-2"></i>Manage Suggestions</h5>
                            </div>
                            <div class="card-body">
                                <?php if (empty($suggestions)): ?>
                                    <p class="text-muted text-center py-4">No suggestions yet.</p>
                                <?php else: ?>
                                    <div class="table-responsive">
                                        <table class="table table-striped">
                                            <thead>
                                                <tr>
                                                    <th>ID</th>
                                                    <th>Content</th>
                                                    <th>User</th>
                                                    <th>Role</th>
                                                    <th>Date</th>
                                                    <th>Action</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($suggestions as $suggestion): ?>
                                                <tr>
                                                    <td><?= $suggestion['id'] ?></td>
                                                    <td style="max-width: 400px; word-wrap: break-word;">
                                                        <?= htmlspecialchars($suggestion['content']) ?>
                                                    </td>
                                                    <td><?= htmlspecialchars($suggestion['username']) ?></td>
                                                    <td>
                                                        <span class="badge <?= $suggestion['role'] === 'admin' ? 'bg-danger' : 'bg-secondary' ?>">
                                                            <?= $suggestion['role'] ?>
                                                        </span>
                                                    </td>
                                                    <td><?= date('M j, H:i', strtotime($suggestion['created_at'])) ?></td>
                                                    <td>
                                                        <a href="?action=delete_suggestion&id=<?= $suggestion['id'] ?>" 
                                                           class="btn btn-danger btn-sm"
                                                           onclick="return confirm('Delete this suggestion?')">
                                                            <i class="fas fa-trash"></i>
                                                        </a>
                                                    </td>
                                                </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <!-- Users Tab -->
                    <div class="tab-pane fade" id="users">
                        <div class="main-content">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0"><i class="fas fa-users me-2"></i>Manage Users</h5>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-striped">
                                        <thead>
                                            <tr>
                                                <th>ID</th>
                                                <th>Username</th>
                                                <th>Role</th>
                                                <th>Joined</th>
                                                <th>Last Upload</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($users as $user): ?>
                                            <tr>
                                                <td><?= $user['id'] ?></td>
                                                <td>
                                                    <?= htmlspecialchars($user['username']) ?>
                                                    <?php if ($user['username'] === 'admin'): ?>
                                                        <span class="badge bg-danger ms-1">ADMIN</span>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <span class="badge <?= $user['role'] === 'admin' ? 'bg-danger' : 'bg-secondary' ?>">
                                                        <?= $user['role'] ?>
                                                    </span>
                                                </td>
                                                <td><?= date('M j, Y', strtotime($user['created_at'])) ?></td>
                                                <td>
                                                    <?= $user['last_upload_at'] ? date('M j, H:i', strtotime($user['last_upload_at'])) : 'Never' ?>
                                                </td>
                                                <td>
                                                    <span class="badge bg-success">Active</span>
                                                </td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Uploads Tab -->
                    <div class="tab-pane fade" id="uploads">
                        <div class="main-content">
                            <div class="card-header bg-success text-white">
                                <h5 class="mb-0"><i class="fas fa-upload me-2"></i>All Uploads</h5>
                            </div>
                            <div class="card-body">
                                <?php if (empty($recent_uploads)): ?>
                                    <p class="text-muted text-center py-4">No uploads yet.</p>
                                <?php else: ?>
                                    <div class="table-responsive">
                                        <table class="table table-striped">
                                            <thead>
                                                <tr>
                                                    <th>ID</th>
                                                    <th>User</th>
                                                    <th>Filename</th>
                                                    <th>Upload Time</th>
                                                    <th>Posts</th>
                                                    <th>Success</th>
                                                    <th>Failed</th>
                                                    <th>Publication</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($recent_uploads as $upload): ?>
                                                <tr>
                                                    <td><?= $upload['id'] ?></td>
                                                    <td>
                                                        <strong><?= htmlspecialchars($upload['username']) ?></strong>
                                                        <?php if ($upload['username'] === 'admin'): ?>
                                                            <span class="badge bg-danger ms-1">ADMIN</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td><?= htmlspecialchars($upload['filename']) ?></td>
                                                    <td><?= date('M j, H:i', strtotime($upload['upload_time'])) ?></td>
                                                    <td>
                                                        <span class="badge bg-primary"><?= $upload['posts_count'] ?></span>
                                                    </td>
                                                    <td>
                                                        <span class="badge bg-success"><?= $upload['success_count'] ?></span>
                                                    </td>
                                                    <td>
                                                        <span class="badge bg-danger"><?= $upload['failed_count'] ?></span>
                                                    </td>
                                                    <td>
                                                        <small class="text-muted"><?= substr($upload['publication_id'] ?? 'N/A', 0, 15) ?>...</small>
                                                    </td>
                                                </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Tab functionality
        document.addEventListener('DOMContentLoaded', function() {
            const triggerTabList = [].slice.call(document.querySelectorAll('a[data-bs-toggle="tab"]'));
            triggerTabList.forEach(function (triggerEl) {
                triggerEl.addEventListener('click', function (event) {
                    event.preventDefault();
                    const tabTrigger = new bootstrap.Tab(triggerEl);
                    tabTrigger.show();
                });
            });
        });
    </script>
</body>
</html>