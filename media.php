<?php
session_start();

// Define CSRF token lifetime (e.g., 30 minutes)
define('CSRF_TOKEN_LIFETIME', 1800);
if (
    !isset($_SESSION['csrf_token_media']) ||
    !isset($_SESSION['csrf_token_media_time']) ||
    (time() - $_SESSION['csrf_token_media_time'] > CSRF_TOKEN_LIFETIME)
) {
    $_SESSION['csrf_token_media'] = bin2hex(random_bytes(32));
    $_SESSION['csrf_token_media_time'] = time();
}

// Connect to the SQLite database.
try {
    $db = new PDO('sqlite:../media.db');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    die("Media Database error: " . htmlspecialchars($e->getMessage()));
}

// Set the directory for file uploads.
$uploadDir = __DIR__ . '/uploads/';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

// If not logged in, process login.
if (!isset($_SESSION['media_user'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
        if (
            !isset($_POST['csrf_token_media']) ||
            $_POST['csrf_token_media'] !== $_SESSION['csrf_token_media'] ||
            (time() - $_SESSION['csrf_token_media_time'] > CSRF_TOKEN_LIFETIME)
        ) {
            die("CSRF token validation failed or expired.");
        }
        $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$_POST['username']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user && password_verify($_POST['password'], $user['password_hash'])) {
            $_SESSION['media_user'] = $user;
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $media_error = "Invalid login credentials for media management.";
        }
    }
    // Display media admin login form.
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Media Manager Login</title>
        <link href="./css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <h1>Media Manager Login</h1>
            <?php if (isset($media_error)): ?>
                <div class="alert alert-danger"><?= htmlspecialchars($media_error) ?></div>
            <?php endif; ?>
            <form method="post">
                <input type="hidden" name="csrf_token_media" value="<?= htmlspecialchars($_SESSION['csrf_token_media']) ?>">
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" name="username" id="username" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" name="password" id="password" class="form-control" required>
                </div>
                <button type="submit" name="login" class="btn btn-primary">Login</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Determine active tab (default is "media").
// We use a GET or POST parameter “tab” so that when forms submit the proper tab is shown.
$tab = $_GET['tab'] ?? $_POST['tab'] ?? 'media';

// ------------------------
// PROCESS POST REQUESTS
// ------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token for every POST request.
    if (
        !isset($_POST['csrf_token_media']) ||
        $_POST['csrf_token_media'] !== $_SESSION['csrf_token_media'] ||
        (time() - $_SESSION['csrf_token_media_time'] > CSRF_TOKEN_LIFETIME)
    ) {
        die("CSRF token validation failed or expired.");
    }

    // ========= Media actions =========
    if (isset($_POST['upload'])) {
        if (isset($_FILES['media_file']) && $_FILES['media_file']['error'] === UPLOAD_ERR_OK) {
            $tmpName = $_FILES['media_file']['tmp_name'];
            $originalName = basename($_FILES['media_file']['name']);
            // Generate a unique file name.
            $ext = pathinfo($originalName, PATHINFO_EXTENSION);
            $newFileName = uniqid('media_', true) . ($ext ? '.' . $ext : '');
            $destination = $uploadDir . $newFileName;
            if (move_uploaded_file($tmpName, $destination)) {
                // Save with an uploaded_at timestamp.
                $stmt = $db->prepare("INSERT INTO media (filename, original_name, file_type, uploaded_at) VALUES (?, ?, ?, datetime('now'))");
                $stmt->execute([$newFileName, $originalName, $_FILES['media_file']['type']]);
                $uploadSuccess = "File uploaded successfully!";
            } else {
                $uploadError = "Failed to move the uploaded file.";
            }
        } else {
            $uploadError = "File upload error.";
        }
    }

    if (isset($_POST['rename'])) {
        $media_id = $_POST['media_id'] ?? '';
        $new_name = trim($_POST['new_name'] ?? '');
        if (empty($new_name)) {
            $renameError = "New name cannot be empty.";
        } else {
            $stmt = $db->prepare("SELECT * FROM media WHERE id = ?");
            $stmt->execute([$media_id]);
            $media = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($media) {
                $oldPath = $uploadDir . $media['filename'];
                // Sanitize the new name.
                $safe_new_name = preg_replace('/[^A-Za-z0-9_\-\.]/', '_', $new_name);
                $newPath = $uploadDir . $safe_new_name;
                if (file_exists($newPath)) {
                    $renameError = "A file with that name already exists.";
                } else {
                    if (rename($oldPath, $newPath)) {
                        $stmt = $db->prepare("UPDATE media SET filename = ?, original_name = ? WHERE id = ?");
                        $stmt->execute([$safe_new_name, $safe_new_name, $media_id]);
                        $renameSuccess = "File renamed successfully.";
                    } else {
                        $renameError = "Error renaming file on disk.";
                    }
                }
            } else {
                $renameError = "Media file not found.";
            }
        }
    }

    if (isset($_POST['delete'])) {
        $media_id = $_POST['media_id'] ?? '';
        $stmt = $db->prepare("SELECT * FROM media WHERE id = ?");
        $stmt->execute([$media_id]);
        $media = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($media) {
            $filePath = $uploadDir . $media['filename'];
            if (file_exists($filePath)) {
                if (!unlink($filePath)) {
                    $deleteError = "Could not delete file from disk.";
                }
            }
            $stmt = $db->prepare("DELETE FROM media WHERE id = ?");
            $stmt->execute([$media_id]);
            $deleteSuccess = "File deleted successfully.";
        } else {
            $deleteError = "Media file not found.";
        }
    }

    // ========= User management actions =========
    if (isset($_POST['add_user'])) {
        $new_username = trim($_POST['new_username'] ?? '');
        $new_password = $_POST['new_password'] ?? '';
        $confirm_new_password = $_POST['confirm_new_password'] ?? '';
        if (empty($new_username) || empty($new_password)) {
            $userError = "Username and password cannot be empty.";
        } elseif ($new_password !== $confirm_new_password) {
            $userError = "Passwords do not match.";
        } else {
            // Check if username already exists.
            $stmt = $db->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
            $stmt->execute([$new_username]);
            if ($stmt->fetchColumn() > 0) {
                $userError = "Username already exists.";
            } else {
                $password_hash = password_hash($new_password, PASSWORD_DEFAULT);
                $stmt = $db->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
                $stmt->execute([$new_username, $password_hash]);
                $userSuccess = "User added successfully.";
            }
        }
    }

    if (isset($_POST['delete_user'])) {
        $user_id = $_POST['user_id'] ?? '';
        // Fetch the user from the database.
        $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $targetUser = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($targetUser) {
            if ($targetUser['username'] === 'admin') {
                $userError = "The admin user cannot be deleted.";
            } elseif ($targetUser['id'] == $_SESSION['media_user']['id']) {
                $userError = "You cannot delete your own account.";
            } else {
                $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
                $stmt->execute([$user_id]);
                $userSuccess = "User deleted successfully.";
            }
        } else {
            $userError = "User not found.";
        }
    }

    if (isset($_POST['update_password'])) {
        $user_id = $_POST['user_id'] ?? '';
        $new_password_update = $_POST['new_password_update'] ?? '';
        $confirm_new_password_update = $_POST['confirm_new_password_update'] ?? '';
        if (empty($new_password_update)) {
            $userError = "New password cannot be empty.";
        } elseif ($new_password_update !== $confirm_new_password_update) {
            $userError = "Passwords do not match.";
        } else {
            $password_hash = password_hash($new_password_update, PASSWORD_DEFAULT);
            $stmt = $db->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
            $stmt->execute([$password_hash, $user_id]);
            $userSuccess = "Password updated successfully.";
        }
    }
} // End POST processing

// ------------------------
// PREPARE DATA FOR THE ACTIVE TAB
// ------------------------

// ------------------------
// MEDIA TAB PREPARATION
// ------------------------
if ($tab === 'media') {
    // Get filter, search, and view parameters.
    $filter = $_GET['filter'] ?? 'all';
    $search = trim($_GET['search'] ?? '');
    $media_view = $_GET['view'] ?? 'thumbnail'; // "thumbnail" or "list"

    $whereClauses = [];
    $params = [];

    if ($filter !== 'all') {
        if ($filter === 'images') {
            $whereClauses[] = "file_type LIKE 'image/%'";
        } elseif ($filter === 'audio') {
            $whereClauses[] = "file_type LIKE 'audio/%'";
        } elseif ($filter === 'video') {
            $whereClauses[] = "file_type LIKE 'video/%'";
        } elseif ($filter === 'documents') {
            $whereClauses[] = "(file_type = 'application/pdf' OR file_type = 'application/msword' OR file_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' OR file_type = 'text/plain')";
        } elseif ($filter === 'other') {
            $whereClauses[] = "NOT (file_type LIKE 'image/%' OR file_type LIKE 'audio/%' OR file_type LIKE 'video/%' OR file_type = 'application/pdf' OR file_type = 'application/msword' OR file_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' OR file_type = 'text/plain')";
        }
    }
    if (!empty($search)) {
        $whereClauses[] = "(original_name LIKE ? OR file_type LIKE ?)";
        $params[] = "%$search%";
        $params[] = "%$search%";
    }
    $whereSQL = count($whereClauses) > 0 ? "WHERE " . implode(" AND ", $whereClauses) : "";

    // Pagination for media: 25 per page.
    $media_page = isset($_GET['media_page']) ? (int)$_GET['media_page'] : 1;
    if ($media_page < 1) { $media_page = 1; }
    $media_limit = 25;
    $media_offset = ($media_page - 1) * $media_limit;

    // Get total media count.
    $countQuery = "SELECT COUNT(*) FROM media $whereSQL";
    $stmtCount = $db->prepare($countQuery);
    $stmtCount->execute($params);
    $totalMedia = $stmtCount->fetchColumn();

    // Get media files with limit and offset.
    $query = "SELECT * FROM media $whereSQL ORDER BY uploaded_at DESC LIMIT :media_limit OFFSET :media_offset";
    $stmt = $db->prepare($query);
    $bindIndex = 1;
    foreach ($params as $param) {
        $stmt->bindValue($bindIndex, $param, PDO::PARAM_STR);
        $bindIndex++;
    }
    $stmt->bindValue(':media_limit', $media_limit, PDO::PARAM_INT);
    $stmt->bindValue(':media_offset', $media_offset, PDO::PARAM_INT);
    $stmt->execute();
    $mediaFiles = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// ------------------------
// USER MANAGEMENT TAB PREPARATION
// ------------------------
if ($tab === 'users') {
    $userSearch = trim($_GET['user_search'] ?? '');
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    if ($page < 1) { $page = 1; }
    $limit = 25;
    $offset = ($page - 1) * $limit;
    if (!empty($userSearch)) {
        $stmt = $db->prepare("SELECT COUNT(*) FROM users WHERE username LIKE ?");
        $stmt->execute(["%$userSearch%"]);
        $totalUsers = $stmt->fetchColumn();

        $stmt = $db->prepare("SELECT * FROM users WHERE username LIKE ? ORDER BY username ASC LIMIT :limit OFFSET :offset");
        $stmt->bindValue(1, "%$userSearch%", PDO::PARAM_STR);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
    } else {
        $stmt = $db->query("SELECT COUNT(*) FROM users");
        $totalUsers = $stmt->fetchColumn();

        $stmt = $db->prepare("SELECT * FROM users ORDER BY username ASC LIMIT :limit OFFSET :offset");
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
    }
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Media Manager</title>
    <link href="./css/bootstrap.min.css" rel="stylesheet">
    <style>
        /* Simple styling for media gallery cards */
        .media-card { margin-bottom: 20px; }
        .media-card img { max-width: 100%; height: auto; }
    </style>
</head>
<body>
    <!-- Navigation tabs -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <div class="container">
        <a class="navbar-brand" href="?tab=media">Media Manager</a>
        <div class="collapse navbar-collapse">
          <ul class="navbar-nav me-auto mb-2 mb-lg-0">
            <li class="nav-item">
              <a class="nav-link <?= ($tab === 'media') ? 'active' : '' ?>" href="?tab=media">Media</a>
            </li>
            <li class="nav-item">
              <a class="nav-link <?= ($tab === 'users') ? 'active' : '' ?>" href="?tab=users">User Management</a>
            </li>
          </ul>
          <span class="navbar-text">
             Logged in as: <?= htmlspecialchars($_SESSION['media_user']['username']) ?> |
             <a href="media_logout.php"  class="btn btn-warning">Logout</a>
          </span>
        </div>
      </div>
    </nav>

    <div class="container mt-5">
    <?php if ($tab === 'media'): ?>
        <h1>Media Manager</h1>
        <!-- Display upload/rename/delete messages -->
        <?php if (isset($uploadError)): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($uploadError) ?></div>
        <?php elseif (isset($uploadSuccess)): ?>
            <div class="alert alert-success"><?= htmlspecialchars($uploadSuccess) ?></div>
        <?php endif; ?>
        <?php if (isset($renameError)): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($renameError) ?></div>
        <?php elseif (isset($renameSuccess)): ?>
            <div class="alert alert-success"><?= htmlspecialchars($renameSuccess) ?></div>
        <?php endif; ?>
        <?php if (isset($deleteError)): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($deleteError) ?></div>
        <?php elseif (isset($deleteSuccess)): ?>
            <div class="alert alert-success"><?= htmlspecialchars($deleteSuccess) ?></div>
        <?php endif; ?>

        <!-- File Upload Form -->
        <form method="post" enctype="multipart/form-data" class="mb-4">
            <input type="hidden" name="csrf_token_media" value="<?= htmlspecialchars($_SESSION['csrf_token_media']) ?>">
            <input type="hidden" name="tab" value="media">
            <div class="mb-3">
                <label for="media_file" class="form-label">Choose file to upload</label>
                <input type="file" name="media_file" id="media_file" class="form-control" required>
            </div>
            <button type="submit" name="upload" class="btn btn-primary">Upload File</button>
        </form>

        <!-- Filter and Search Form -->
        <form method="get" class="row g-3 mb-4">
            <input type="hidden" name="tab" value="media">
            <div class="col-md-3">
                <select name="filter" class="form-select">
                    <option value="all" <?= ($filter === 'all') ? 'selected' : '' ?>>All Types</option>
                    <option value="images" <?= ($filter === 'images') ? 'selected' : '' ?>>Images</option>
                    <option value="audio" <?= ($filter === 'audio') ? 'selected' : '' ?>>Audio</option>
                    <option value="video" <?= ($filter === 'video') ? 'selected' : '' ?>>Video</option>
                    <option value="documents" <?= ($filter === 'documents') ? 'selected' : '' ?>>Documents</option>
                    <option value="other" <?= ($filter === 'other') ? 'selected' : '' ?>>Other</option>
                </select>
            </div>
            <div class="col-md-3">
                <input type="text" name="search" placeholder="Search media files..." class="form-control" value="<?= htmlspecialchars($search) ?>">
            </div>
            <div class="col-md-3">
                <select name="view" class="form-select">
                    <option value="thumbnail" <?= ($media_view==='thumbnail') ? 'selected' : '' ?>>Thumbnail View</option>
                    <option value="list" <?= ($media_view==='list') ? 'selected' : '' ?>>List View</option>
                </select>
            </div>
            <div class="col-md-3">
                <button type="submit" class="btn btn-primary w-100">Filter/Search</button>
            </div>
        </form>

        <?php
        // Determine base URL parameters for pagination links.
        $baseParams = "tab=media&filter=" . urlencode($filter) . "&search=" . urlencode($search) . "&view=" . urlencode($media_view);
        ?>

        <!-- Media Listing -->
        <?php if ($media_view === 'thumbnail'): ?>
            <div class="row">
                <?php if (empty($mediaFiles)): ?>
                    <p>No media files found.</p>
                <?php else: ?>
                    <?php foreach ($mediaFiles as $media):
                        // Build file URL.
                        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https" : "http";
                        $baseDir = rtrim(dirname($_SERVER['PHP_SELF']), '/\\');
                        $fileUrl = $scheme . "://" . $_SERVER['HTTP_HOST'] . ($baseDir ? $baseDir : "") . "/uploads/" . $media['filename'];
                    ?>
                    <div class="col-md-4 media-card">
                        <div class="card">
                            <?php if (strpos($media['file_type'], 'image/') === 0): ?>
                                <img src="<?= htmlspecialchars($fileUrl) ?>" class="card-img-top" alt="<?= htmlspecialchars($media['original_name']) ?>">
                            <?php else: ?>
                                <div class="card-body text-center">
                                    <p class="card-text"><?= htmlspecialchars($media['original_name']) ?></p>
                                </div>
                            <?php endif; ?>
                            <div class="card-footer">
                                <!-- "View" button opens the media file in a new tab -->
                                <a href="<?= htmlspecialchars($fileUrl) ?>" target="_blank" class="btn btn-sm btn-info mb-2">View</a>
                                <!-- "Copy URL" button uses JavaScript to copy the URL to the clipboard -->
                                <button type="button" class="btn btn-sm btn-secondary mb-2 btn-copy" data-url="<?= htmlspecialchars($fileUrl) ?>">Copy URL</button>
                                <!-- Rename Form -->
                                <form method="post" class="mb-2">
                                    <input type="hidden" name="csrf_token_media" value="<?= htmlspecialchars($_SESSION['csrf_token_media']) ?>">
                                    <input type="hidden" name="tab" value="media">
                                    <input type="hidden" name="media_id" value="<?= htmlspecialchars($media['id']) ?>">
                                    <div class="input-group">
                                        <input type="text" name="new_name" class="form-control" placeholder="New filename" value="<?= htmlspecialchars($media['filename']) ?>">
                                        <button type="submit" name="rename" class="btn btn-sm btn-secondary">Rename</button>
                                    </div>
                                </form>
                                <!-- Delete Form -->
                                <form method="post" onsubmit="return confirm('Are you sure you want to delete this file?');">
                                    <input type="hidden" name="csrf_token_media" value="<?= htmlspecialchars($_SESSION['csrf_token_media']) ?>">
                                    <input type="hidden" name="tab" value="media">
                                    <input type="hidden" name="media_id" value="<?= htmlspecialchars($media['id']) ?>">
                                    <button type="submit" name="delete" class="btn btn-sm btn-danger w-100">Delete</button>
                                </form>
                            </div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        <?php else: // List view ?>
            <?php if (empty($mediaFiles)): ?>
                <p>No media files found.</p>
            <?php else: ?>
                <table class="table table-bordered">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Original Name</th>
                            <th>File Type</th>
                            <th>Uploaded At</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($mediaFiles as $media):
                            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https" : "http";
                            $baseDir = rtrim(dirname($_SERVER['PHP_SELF']), '/\\');
                            $fileUrl = $scheme . "://" . $_SERVER['HTTP_HOST'] . ($baseDir ? $baseDir : "") . "/uploads/" . $media['filename'];
                        ?>
                        <tr>
                            <td><?= htmlspecialchars($media['id']) ?></td>
                            <td><?= htmlspecialchars($media['original_name']) ?></td>
                            <td><?= htmlspecialchars($media['file_type']) ?></td>
                            <td><?= htmlspecialchars($media['uploaded_at']) ?></td>
                            <td>
                                <a href="<?= htmlspecialchars($fileUrl) ?>" target="_blank" class="btn btn-sm btn-info">View</a>
                                <button type="button" class="btn btn-sm btn-secondary btn-copy" data-url="<?= htmlspecialchars($fileUrl) ?>">Copy URL</button>
                                <form method="post" class="d-inline-block">
                                    <input type="hidden" name="csrf_token_media" value="<?= htmlspecialchars($_SESSION['csrf_token_media']) ?>">
                                    <input type="hidden" name="tab" value="media">
                                    <input type="hidden" name="media_id" value="<?= htmlspecialchars($media['id']) ?>">
                                    <div class="input-group input-group-sm mt-1">
                                        <input type="text" name="new_name" class="form-control" placeholder="New filename" value="<?= htmlspecialchars($media['filename']) ?>">
                                        <button type="submit" name="rename" class="btn btn-secondary">Rename</button>
                                    </div>
                                </form>
                                <form method="post" class="d-inline-block mt-1" onsubmit="return confirm('Are you sure you want to delete this file?');">
                                    <input type="hidden" name="csrf_token_media" value="<?= htmlspecialchars($_SESSION['csrf_token_media']) ?>">
                                    <input type="hidden" name="tab" value="media">
                                    <input type="hidden" name="media_id" value="<?= htmlspecialchars($media['id']) ?>">
                                    <button type="submit" name="delete" class="btn btn-danger btn-sm">Delete</button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        <?php endif; ?>

        <!-- Pagination Links for Media -->
        <?php 
        $totalMediaPages = ceil($totalMedia / $media_limit);
        if ($totalMediaPages > 1): ?>
        <nav>
            <ul class="pagination">
                <?php for($i = 1; $i <= $totalMediaPages; $i++): ?>
                    <li class="page-item <?= ($i == $media_page) ? 'active' : '' ?>">
                        <a class="page-link" href="?<?= $baseParams ?>&media_page=<?= $i ?>"><?= $i ?></a>
                    </li>
                <?php endfor; ?>
            </ul>
        </nav>
        <?php endif; ?>

        <!-- JavaScript for the "Copy URL" functionality -->
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('.btn-copy').forEach(function(button) {
                button.addEventListener('click', function() {
                    var url = this.getAttribute('data-url');
                    navigator.clipboard.writeText(url).then(function() {
                        alert('URL copied to clipboard!');
                    }, function(err) {
                        alert('Failed to copy URL');
                    });
                });
            });
        });
        </script>

    <?php elseif ($tab === 'users'): ?>
        <h1>User Management</h1>
        <?php if (isset($userError)): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($userError) ?></div>
        <?php elseif (isset($userSuccess)): ?>
            <div class="alert alert-success"><?= htmlspecialchars($userSuccess) ?></div>
        <?php endif; ?>

        <!-- Add New User Form -->
        <form method="post" class="mb-4">
            <input type="hidden" name="csrf_token_media" value="<?= htmlspecialchars($_SESSION['csrf_token_media']) ?>">
            <input type="hidden" name="tab" value="users">
            <div class="mb-3">
                <label class="form-label">Username</label>
                <input type="text" name="new_username" class="form-control" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <input type="password" name="new_password" class="form-control" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Confirm Password</label>
                <input type="password" name="confirm_new_password" class="form-control" required>
            </div>
            <button type="submit" name="add_user" class="btn btn-primary">Add User</button>
        </form>

        <!-- Search Users Form -->
        <form method="get" class="row g-3 mb-4">
            <input type="hidden" name="tab" value="users">
            <div class="col-md-6">
                <input type="text" name="user_search" placeholder="Search users..." class="form-control" value="<?= htmlspecialchars($userSearch) ?>">
            </div>
            <div class="col-md-6">
                <button type="submit" class="btn btn-primary w-100">Search Users</button>
            </div>
        </form>

        <!-- Users List Table with Separate Delete Column -->
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Change Password</th>
                    <th>Delete</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($users as $user): ?>
                <tr>
                    <td><?= htmlspecialchars($user['id']) ?></td>
                    <td><?= htmlspecialchars($user['username']) ?></td>
                    <td>
                        <!-- Change Password Form -->
                        <form method="post" class="d-inline-block">
                            <input type="hidden" name="csrf_token_media" value="<?= htmlspecialchars($_SESSION['csrf_token_media']) ?>">
                            <input type="hidden" name="tab" value="users">
                            <input type="hidden" name="user_id" value="<?= htmlspecialchars($user['id']) ?>">
                            <input type="password" name="new_password_update" placeholder="New Password" required>
                            <input type="password" name="confirm_new_password_update" placeholder="Confirm Password" required>
                            <button type="submit" name="update_password" class="btn btn-sm btn-secondary">Change Password</button>
                        </form>
                    </td>
                    <td>
                        <?php if ($user['username'] !== $_SESSION['media_user']['username'] && $user['username'] !== 'admin'): ?>
                        <form method="post" onsubmit="return confirm('Are you sure you want to delete this user?');">
                            <input type="hidden" name="csrf_token_media" value="<?= htmlspecialchars($_SESSION['csrf_token_media']) ?>">
                            <input type="hidden" name="tab" value="users">
                            <input type="hidden" name="user_id" value="<?= htmlspecialchars($user['id']) ?>">
                            <button type="submit" name="delete_user" class="btn btn-sm btn-danger">Delete</button>
                        </form>
                        <?php else: ?>
                            <!-- Optionally, you can show a disabled button or text -->
                            <span class="text-muted">N/A</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <!-- Pagination Links for Users -->
        <?php 
        $totalPages = ceil($totalUsers / $limit);
        if ($totalPages > 1): ?>
        <nav>
            <ul class="pagination">
                <?php for($i = 1; $i <= $totalPages; $i++): ?>
                    <li class="page-item <?= ($i == $page) ? 'active' : '' ?>">
                        <a class="page-link" href="?tab=users&page=<?= $i ?><?= (!empty($userSearch)) ? '&user_search=' . urlencode($userSearch) : '' ?>"><?= $i ?></a>
                    </li>
                <?php endfor; ?>
            </ul>
        </nav>
        <?php endif; ?>

    <?php endif; ?>
    </div>
</body>
</html>
