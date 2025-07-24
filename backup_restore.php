<?php
require_once 'dbconfig.php';

// Check admin authentication
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header("Location: admin_login.php");
    exit();
}

if (!validate_session($conn, 'admin', $_SESSION['admin_username'])) {
    session_destroy();
    header("Location: admin_login.php");
    exit();
}

$error_message = '';
$success_message = '';

// Create backups directory if it doesn't exist
$backup_dir = 'backups/';
if (!is_dir($backup_dir)) {
    mkdir($backup_dir, 0755, true);
}

// Handle backup creation
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'create_backup') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        log_security_event($conn, 'csrf_violation', 'high', 'CSRF token validation failed for backup creation', $_SESSION['admin_username']);
        $error_message = 'Security validation failed. Please try again.';
    } else {
        try {
            $timestamp = date('Y-m-d_H-i-s');
            $filename = "full_backup_{$timestamp}.sql";
            $filepath = $backup_dir . $filename;
            
            // Generate full database backup
            $sql_dump = generateFullBackup($conn);
            
            if (file_put_contents($filepath, $sql_dump)) {
                $file_size = filesize($filepath);
                log_activity($conn, 'admin', $_SESSION['admin_username'], 'backup_created', null, null, null, [
                    'filename' => $filename,
                    'size' => $file_size
                ]);
                $success_message = "Full backup created successfully! File: $filename (" . formatFileSize($file_size) . ")";
            } else {
                $error_message = 'Failed to create backup file.';
            }
            
        } catch(Exception $e) {
            error_log("Backup creation error: " . $e->getMessage());
            $error_message = 'An error occurred while creating backup: ' . $e->getMessage();
        }
    }
}

// Handle backup restore
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'restore_backup') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        log_security_event($conn, 'csrf_violation', 'high', 'CSRF token validation failed for backup restore', $_SESSION['admin_username']);
        $error_message = 'Security validation failed. Please try again.';
    } else {
        $backup_file = $_POST['backup_file'] ?? '';
        $confirm_restore = $_POST['confirm_restore'] ?? '';
        
        if ($confirm_restore !== 'RESTORE NOW') {
            $error_message = 'Please type "RESTORE NOW" exactly to confirm the restore operation.';
        } else if (empty($backup_file) || !file_exists($backup_dir . $backup_file)) {
            $error_message = 'Backup file not found.';
        } else {
            try {
                $sql_content = file_get_contents($backup_dir . $backup_file);
                
                if ($sql_content === false) {
                    throw new Exception('Unable to read backup file.');
                }
                
                // Execute restore
                $conn->exec('SET FOREIGN_KEY_CHECKS = 0');
                $conn->beginTransaction();
                
                // Split and execute SQL statements
                $statements = preg_split('/;\s*$/m', $sql_content);
                $executed_statements = 0;
                
                foreach ($statements as $statement) {
                    $statement = trim($statement);
                    if (!empty($statement) && !preg_match('/^--/', $statement)) {
                        $conn->exec($statement);
                        $executed_statements++;
                    }
                }
                
                $conn->commit();
                $conn->exec('SET FOREIGN_KEY_CHECKS = 1');
                
                log_activity($conn, 'admin', $_SESSION['admin_username'], 'backup_restored', null, null, null, [
                    'backup_file' => $backup_file,
                    'statements_executed' => $executed_statements
                ]);
                
                $success_message = "Backup restored successfully! Executed $executed_statements SQL statements.";
                
            } catch(Exception $e) {
                if ($conn->inTransaction()) {
                    $conn->rollBack();
                }
                $conn->exec('SET FOREIGN_KEY_CHECKS = 1');
                error_log("Backup restore error: " . $e->getMessage());
                $error_message = 'An error occurred while restoring backup: ' . $e->getMessage();
            }
        }
    }
}

// Handle backup file deletion
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'delete_backup') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Security validation failed.';
    } else {
        $backup_file = $_POST['backup_file'] ?? '';
        $filepath = $backup_dir . $backup_file;
        
        if (file_exists($filepath) && unlink($filepath)) {
            log_activity($conn, 'admin', $_SESSION['admin_username'], 'backup_deleted', null, null, null, ['filename' => $backup_file]);
            $success_message = "Backup file deleted: $backup_file";
        } else {
            $error_message = 'Failed to delete backup file.';
        }
    }
}

// Get existing backup files
$backup_files = [];
if (is_dir($backup_dir)) {
    $files = scandir($backup_dir);
    foreach ($files as $file) {
        if (pathinfo($file, PATHINFO_EXTENSION) === 'sql') {
            $filepath = $backup_dir . $file;
            $backup_files[] = [
                'filename' => $file,
                'size' => filesize($filepath),
                'date' => filemtime($filepath)
            ];
        }
    }
    // Sort by date (newest first)
    usort($backup_files, function($a, $b) {
        return $b['date'] - $a['date'];
    });
}

// Get database statistics
try {
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM subject_pools WHERE is_active = 1");
    $stmt->execute();
    $total_pools = $stmt->fetch()['count'];
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM student_registrations");
    $stmt->execute();
    $total_registrations = $stmt->fetch()['count'];
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM subject_allotments");
    $stmt->execute();
    $total_allotments = $stmt->fetch()['count'];
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM student_academic_data");
    $stmt->execute();
    $total_academic = $stmt->fetch()['count'];
    
} catch(Exception $e) {
    $total_pools = $total_registrations = $total_allotments = $total_academic = 0;
}

$csrf_token = generate_csrf_token();

// Helper functions
function generateFullBackup($conn) {
    $sql_dump = "-- Subject Allotment System Full Database Backup\n";
    $sql_dump .= "-- Generated on: " . date('Y-m-d H:i:s') . "\n";
    $sql_dump .= "-- Database: " . DB_NAME . "\n\n";
    $sql_dump .= "SET FOREIGN_KEY_CHECKS = 0;\n";
    $sql_dump .= "SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';\n";
    $sql_dump .= "SET AUTOCOMMIT = 0;\n";
    $sql_dump .= "START TRANSACTION;\n\n";
    
    // All tables to backup
    $tables = [
        'admin',
        'subject_pools',
        'student_academic_data',
        'student_registrations',
        'subject_allotments',
        'activity_logs',
        'login_logs',
        'security_logs',
        'user_sessions',
        'form_submissions'
    ];
    
    foreach ($tables as $table) {
        try {
            // Get table structure
            $stmt = $conn->prepare("SHOW CREATE TABLE `$table`");
            $stmt->execute();
            $create_table = $stmt->fetch();
            
            if ($create_table) {
                $sql_dump .= "-- Structure for table `$table`\n";
                $sql_dump .= "DROP TABLE IF EXISTS `$table`;\n";
                $sql_dump .= $create_table['Create Table'] . ";\n\n";
                
                // Get table data
                $stmt = $conn->prepare("SELECT * FROM `$table`");
                $stmt->execute();
                $rows = $stmt->fetchAll();
                
                if (!empty($rows)) {
                    $sql_dump .= "-- Data for table `$table`\n";
                    
                    foreach ($rows as $row) {
                        $columns = array_keys($row);
                        $column_list = '`' . implode('`, `', $columns) . '`';
                        
                        $values = array_map(function($value) use ($conn) {
                            return $value === null ? 'NULL' : $conn->quote($value);
                        }, array_values($row));
                        
                        $sql_dump .= "INSERT INTO `$table` ($column_list) VALUES (" . implode(', ', $values) . ");\n";
                    }
                    $sql_dump .= "\n";
                }
            }
        } catch(Exception $e) {
            // Skip tables that don't exist
            continue;
        }
    }
    
    $sql_dump .= "COMMIT;\n";
    $sql_dump .= "SET FOREIGN_KEY_CHECKS = 1;\n";
    return $sql_dump;
}

function formatFileSize($bytes) {
    if ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } else {
        return $bytes . ' bytes';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup & Restore - Subject Allotment System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .backup-card {
            border-left: 5px solid #28a745;
        }
        .restore-card {
            border-left: 5px solid #dc3545;
        }
        .stats-card {
            border-left: 5px solid #007bff;
        }
        .files-card {
            border-left: 5px solid #ffc107;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="admin_dashboard.php">
                <i class="fas fa-graduation-cap me-2"></i>
                Subject Allotment System
            </a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="admin_dashboard.php">
                    <i class="fas fa-arrow-left me-1"></i>Back to Dashboard
                </a>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2><i class="fas fa-database me-2"></i>Backup & Restore System</h2>
        </div>

        <?php if (!empty($error_message)): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <?php echo htmlspecialchars($error_message); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php if (!empty($success_message)): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="fas fa-check-circle me-2"></i>
                <?php echo htmlspecialchars($success_message); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <div class="row">
            <!-- Left Column - Create Backup -->
            <div class="col-lg-6">
                <!-- Database Statistics -->
                <div class="card stats-card mb-4">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">
                            <i class="fas fa-chart-bar me-2"></i>Database Overview
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="row text-center">
                            <div class="col-6 col-md-3 mb-3">
                                <h4 class="text-primary"><?php echo number_format($total_pools); ?></h4>
                                <small class="text-muted">Subject Pools</small>
                            </div>
                            <div class="col-6 col-md-3 mb-3">
                                <h4 class="text-success"><?php echo number_format($total_registrations); ?></h4>
                                <small class="text-muted">Registrations</small>
                            </div>
                            <div class="col-6 col-md-3 mb-3">
                                <h4 class="text-warning"><?php echo number_format($total_allotments); ?></h4>
                                <small class="text-muted">Allotments</small>
                            </div>
                            <div class="col-6 col-md-3 mb-3">
                                <h4 class="text-info"><?php echo number_format($total_academic); ?></h4>
                                <small class="text-muted">Academic Data</small>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Create Backup -->
                <div class="card backup-card">
                    <div class="card-header bg-success text-white">
                        <h5 class="mb-0">
                            <i class="fas fa-download me-2"></i>Create Full Backup
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-2"></i>
                            <strong>Full Backup includes:</strong>
                            <ul class="mb-0 mt-2">
                                <li>All admin accounts</li>
                                <li>All subject pools and configurations</li>
                                <li>All student registrations and academic data</li>
                                <li>All subject allotments</li>
                                <li>All system logs and activity history</li>
                            </ul>
                        </div>

                        <form method="POST" action="" id="backupForm">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <input type="hidden" name="action" value="create_backup">
                            
                            <div class="d-grid">
                                <button type="submit" class="btn btn-success btn-lg">
                                    <i class="fas fa-download me-2"></i>Create Full Backup Now
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Right Column - Restore -->
            <div class="col-lg-6">
                <!-- Restore from Backup -->
                <div class="card restore-card">
                    <div class="card-header bg-danger text-white">
                        <h5 class="mb-0">
                            <i class="fas fa-undo me-2"></i>Restore from Backup
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            <strong>⚠️ WARNING:</strong> Restoring will completely replace all current data with the backup data. This action cannot be undone!
                        </div>

                        <form method="POST" action="" id="restoreForm">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <input type="hidden" name="action" value="restore_backup">

                            <div class="mb-3">
                                <label for="backup_file" class="form-label">
                                    <i class="fas fa-file-archive me-2"></i>Select Backup File:
                                </label>
                                <select class="form-select" name="backup_file" id="backup_file" required>
                                    <option value="">Choose a backup file...</option>
                                    <?php foreach ($backup_files as $file): ?>
                                        <option value="<?php echo htmlspecialchars($file['filename']); ?>">
                                            <?php echo htmlspecialchars($file['filename']); ?> 
                                            (<?php echo formatFileSize($file['size']); ?> - <?php echo date('M j, Y H:i', $file['date']); ?>)
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="mb-3">
                                <label for="confirm_restore" class="form-label text-danger">
                                    <i class="fas fa-shield-alt me-2"></i>Type "RESTORE NOW" to confirm:
                                </label>
                                <input type="text" class="form-control" name="confirm_restore" id="confirm_restore" 
                                       placeholder="Type RESTORE NOW" autocomplete="off">
                            </div>

                            <div class="d-grid">
                                <button type="submit" class="btn btn-danger btn-lg" id="restoreBtn" disabled>
                                    <i class="fas fa-undo me-2"></i>Restore Backup
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <!-- Backup Files List -->
        <div class="card files-card mt-4">
            <div class="card-header bg-warning text-dark d-flex justify-content-between align-items-center">
                <h5 class="mb-0">
                    <i class="fas fa-file-archive me-2"></i>Available Backup Files
                </h5>
                <span class="badge bg-dark"><?php echo count($backup_files); ?> files</span>
            </div>
            <div class="card-body">
                <?php if (empty($backup_files)): ?>
                    <div class="text-center text-muted py-5">
                        <i class="fas fa-file-archive fa-4x mb-3"></i>
                        <h5>No Backup Files Found</h5>
                        <p>Create your first backup using the button above.</p>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th><i class="fas fa-file me-2"></i>Filename</th>
                                    <th><i class="fas fa-weight me-2"></i>Size</th>
                                    <th><i class="fas fa-calendar me-2"></i>Created</th>
                                    <th><i class="fas fa-cogs me-2"></i>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($backup_files as $file): ?>
                                <tr>
                                    <td>
                                        <i class="fas fa-file-archive me-2 text-warning"></i>
                                        <strong><?php echo htmlspecialchars($file['filename']); ?></strong>
                                    </td>
                                    <td>
                                        <span class="badge bg-info"><?php echo formatFileSize($file['size']); ?></span>
                                    </td>
                                    <td><?php echo date('M j, Y H:i:s', $file['date']); ?></td>
                                    <td>
                                        <div class="btn-group btn-group-sm">
                                            <a href="<?php echo $backup_dir . htmlspecialchars($file['filename']); ?>" 
                                               class="btn btn-outline-success" download 
                                               title="Download backup">
                                                <i class="fas fa-download"></i>
                                            </a>
                                            <button type="button" class="btn btn-outline-danger" 
                                                    onclick="deleteBackup('<?php echo htmlspecialchars($file['filename']); ?>')"
                                                    title="Delete backup">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
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

    <!-- Delete Backup Modal -->
    <div class="modal fade" id="deleteBackupModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-exclamation-triangle me-2"></i>Delete Backup File
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete the backup file:</p>
                    <p class="text-center"><strong id="deleteFileName"></strong></p>
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        This action cannot be undone!
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <form method="POST" action="" style="display: inline;">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <input type="hidden" name="action" value="delete_backup">
                        <input type="hidden" name="backup_file" id="deleteBackupFile">
                        <button type="submit" class="btn btn-danger">
                            <i class="fas fa-trash me-2"></i>Delete Backup
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Restore confirmation handling
        document.getElementById('confirm_restore').addEventListener('input', function() {
            const backupFile = document.getElementById('backup_file').value;
            const confirmText = this.value;
            const restoreBtn = document.getElementById('restoreBtn');
            
            if (backupFile && confirmText === 'RESTORE NOW') {
                restoreBtn.disabled = false;
                restoreBtn.classList.remove('btn-danger');
                restoreBtn.classList.add('btn-outline-danger');
            } else {
                restoreBtn.disabled = true;
                restoreBtn.classList.remove('btn-outline-danger');
                restoreBtn.classList.add('btn-danger');
            }
        });

        document.getElementById('backup_file').addEventListener('change', function() {
            document.getElementById('confirm_restore').dispatchEvent(new Event('input'));
        });

        // Form submission handlers
        document.getElementById('backupForm').addEventListener('submit', function() {
            const btn = this.querySelector('button[type="submit"]');
            btn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Creating Backup...';
            btn.disabled = true;
        });

        document.getElementById('restoreForm').addEventListener('submit', function(e) {
            if (!confirm('Are you absolutely sure you want to restore this backup?\n\nThis will permanently replace ALL current data!\n\nThis action cannot be undone!')) {
                e.preventDefault();
                return;
            }
            
            const btn = document.getElementById('restoreBtn');
            btn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Restoring...';
            btn.disabled = true;
        });

        // Delete backup function
        function deleteBackup(filename) {
            document.getElementById('deleteFileName').textContent = filename;
            document.getElementById('deleteBackupFile').value = filename;
            
            const modal = new bootstrap.Modal(document.getElementById('deleteBackupModal'));
            modal.show();
        }

        // Prevent form resubmission
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }

        // Auto-refresh every 30 seconds to show new backups
        setTimeout(function() {
            window.location.reload();
        }, 30000);
    </script>
</body>
</html>