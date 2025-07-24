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
$deletion_results = [];

// Handle deletion requests
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        log_security_event($conn, 'csrf_violation', 'high', 'CSRF token validation failed for data deletion', $_SESSION['admin_username']);
        $error_message = 'Security validation failed. Please try again.';
    } else if (!prevent_resubmit($conn, 'admin', $_SESSION['admin_username'], 'delete_data_operation')) {
        $error_message = 'Operation already in progress. Please refresh the page.';
    } else {
        $action = $_POST['action'] ?? '';
        $confirm_text = $_POST['confirm_text'] ?? '';
        
        // Require confirmation text "DELETE ALL"
        if ($confirm_text !== 'DELETE ALL') {
            $error_message = 'Please type "DELETE ALL" exactly to confirm the operation.';
        } else {
            try {
                $conn->beginTransaction();
                $deleted_counts = [];
                
                switch ($action) {
                    case 'delete_allotments':
                        // Delete all subject allotments
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM subject_allotments");
                        $stmt->execute();
                        $count = $stmt->fetch()['count'];
                        
                        if ($count > 0) {
                            $stmt = $conn->prepare("DELETE FROM subject_allotments");
                            $stmt->execute();
                            $deleted_counts['Subject Allotments'] = $count;
                        }
                        break;
                        
                    case 'delete_registrations':
                        // Delete allotments first (foreign key dependency)
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM subject_allotments");
                        $stmt->execute();
                        $allotment_count = $stmt->fetch()['count'];
                        
                        if ($allotment_count > 0) {
                            $stmt = $conn->prepare("DELETE FROM subject_allotments");
                            $stmt->execute();
                            $deleted_counts['Subject Allotments'] = $allotment_count;
                        }
                        
                        // Then delete registrations
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM student_registrations");
                        $stmt->execute();
                        $reg_count = $stmt->fetch()['count'];
                        
                        if ($reg_count > 0) {
                            $stmt = $conn->prepare("DELETE FROM student_registrations");
                            $stmt->execute();
                            $deleted_counts['Student Registrations'] = $reg_count;
                        }
                        break;
                        
                    case 'delete_academic_data':
                        // Delete student academic data
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM student_academic_data");
                        $stmt->execute();
                        $count = $stmt->fetch()['count'];
                        
                        if ($count > 0) {
                            $stmt = $conn->prepare("DELETE FROM student_academic_data");
                            $stmt->execute();
                            $deleted_counts['Academic Data'] = $count;
                        }
                        break;
                        
                    case 'delete_subject_pools':
                        // Delete in order: allotments -> registrations -> subject pools
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM subject_allotments");
                        $stmt->execute();
                        $allotment_count = $stmt->fetch()['count'];
                        
                        if ($allotment_count > 0) {
                            $stmt = $conn->prepare("DELETE FROM subject_allotments");
                            $stmt->execute();
                            $deleted_counts['Subject Allotments'] = $allotment_count;
                        }
                        
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM student_registrations");
                        $stmt->execute();
                        $reg_count = $stmt->fetch()['count'];
                        
                        if ($reg_count > 0) {
                            $stmt = $conn->prepare("DELETE FROM student_registrations");
                            $stmt->execute();
                            $deleted_counts['Student Registrations'] = $reg_count;
                        }
                        
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM subject_pools WHERE is_active = 1");
                        $stmt->execute();
                        $pool_count = $stmt->fetch()['count'];
                        
                        if ($pool_count > 0) {
                            $stmt = $conn->prepare("UPDATE subject_pools SET is_active = 0");
                            $stmt->execute();
                            $deleted_counts['Subject Pools (Deactivated)'] = $pool_count;
                        }
                        break;
                        
                    case 'delete_logs':
                        // Delete system logs
                        $tables = ['activity_logs', 'login_logs', 'security_logs'];
                        foreach ($tables as $table) {
                            $stmt = $conn->prepare("SELECT COUNT(*) as count FROM $table");
                            $stmt->execute();
                            $count = $stmt->fetch()['count'];
                            
                            if ($count > 0) {
                                $stmt = $conn->prepare("DELETE FROM $table");
                                $stmt->execute();
                                $deleted_counts[ucwords(str_replace('_', ' ', $table))] = $count;
                            }
                        }
                        break;
                        
                    case 'delete_sessions':
                        // Delete user sessions and form submissions
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM user_sessions");
                        $stmt->execute();
                        $session_count = $stmt->fetch()['count'];
                        
                        if ($session_count > 0) {
                            $stmt = $conn->prepare("DELETE FROM user_sessions");
                            $stmt->execute();
                            $deleted_counts['User Sessions'] = $session_count;
                        }
                        
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM form_submissions");
                        $stmt->execute();
                        $form_count = $stmt->fetch()['count'];
                        
                        if ($form_count > 0) {
                            $stmt = $conn->prepare("DELETE FROM form_submissions");
                            $stmt->execute();
                            $deleted_counts['Form Submissions'] = $form_count;
                        }
                        break;
                        
                    case 'delete_all_student_data':
                        // Delete everything related to students (respecting dependencies)
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM subject_allotments");
                        $stmt->execute();
                        $allotment_count = $stmt->fetch()['count'];
                        
                        if ($allotment_count > 0) {
                            $stmt = $conn->prepare("DELETE FROM subject_allotments");
                            $stmt->execute();
                            $deleted_counts['Subject Allotments'] = $allotment_count;
                        }
                        
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM student_registrations");
                        $stmt->execute();
                        $reg_count = $stmt->fetch()['count'];
                        
                        if ($reg_count > 0) {
                            $stmt = $conn->prepare("DELETE FROM student_registrations");
                            $stmt->execute();
                            $deleted_counts['Student Registrations'] = $reg_count;
                        }
                        
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM student_academic_data");
                        $stmt->execute();
                        $academic_count = $stmt->fetch()['count'];
                        
                        if ($academic_count > 0) {
                            $stmt = $conn->prepare("DELETE FROM student_academic_data");
                            $stmt->execute();
                            $deleted_counts['Academic Data'] = $academic_count;
                        }
                        break;
                        
                    case 'reset_all_data':
                        // Complete system reset (excluding admin accounts)
                        $tables_to_clear = [
                            'subject_allotments',
                            'student_registrations', 
                            'student_academic_data',
                            'activity_logs',
                            'login_logs',
                            'security_logs',
                            'user_sessions',
                            'form_submissions'
                        ];
                        
                        foreach ($tables_to_clear as $table) {
                            $stmt = $conn->prepare("SELECT COUNT(*) as count FROM $table");
                            $stmt->execute();
                            $count = $stmt->fetch()['count'];
                            
                            if ($count > 0) {
                                $stmt = $conn->prepare("DELETE FROM $table");
                                $stmt->execute();
                                $deleted_counts[ucwords(str_replace('_', ' ', $table))] = $count;
                            }
                        }
                        
                        // Deactivate subject pools
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM subject_pools WHERE is_active = 1");
                        $stmt->execute();
                        $pool_count = $stmt->fetch()['count'];
                        
                        if ($pool_count > 0) {
                            $stmt = $conn->prepare("UPDATE subject_pools SET is_active = 0");
                            $stmt->execute();
                            $deleted_counts['Subject Pools (Deactivated)'] = $pool_count;
                        }
                        break;
                        
                    default:
                        throw new Exception('Invalid action specified.');
                }
                
                $conn->commit();
                
                // Log the deletion activity
                log_activity($conn, 'admin', $_SESSION['admin_username'], 'bulk_data_deletion', null, null, null, [
                    'action' => $action,
                    'deleted_counts' => $deleted_counts,
                    'admin_user' => $_SESSION['admin_username']
                ]);
                
                log_security_event($conn, 'bulk_data_deletion', 'high', "Admin {$_SESSION['admin_username']} performed bulk deletion: $action", $_SESSION['admin_username']);
                
                $deletion_results = $deleted_counts;
                
                if (empty($deleted_counts)) {
                    $success_message = 'Operation completed successfully. No data found to delete.';
                } else {
                    $total_deleted = array_sum($deleted_counts);
                    $success_message = "Deletion completed successfully! Total records affected: $total_deleted";
                }
                
            } catch(Exception $e) {
                $conn->rollBack();
                error_log("Bulk deletion error: " . $e->getMessage());
                $error_message = 'An error occurred during deletion: ' . $e->getMessage();
            }
        }
    }
}

// Get current data counts for display
try {
    $data_counts = [];
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM subject_pools WHERE is_active = 1");
    $stmt->execute();
    $data_counts['subject_pools'] = $stmt->fetch()['count'];
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM student_registrations");
    $stmt->execute();
    $data_counts['student_registrations'] = $stmt->fetch()['count'];
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM subject_allotments");
    $stmt->execute();
    $data_counts['subject_allotments'] = $stmt->fetch()['count'];
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM student_academic_data");
    $stmt->execute();
    $data_counts['academic_data'] = $stmt->fetch()['count'];
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM activity_logs");
    $stmt->execute();
    $data_counts['activity_logs'] = $stmt->fetch()['count'];
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM login_logs");
    $stmt->execute();
    $data_counts['login_logs'] = $stmt->fetch()['count'];
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM security_logs");
    $stmt->execute();
    $data_counts['security_logs'] = $stmt->fetch()['count'];
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM user_sessions");
    $stmt->execute();
    $data_counts['user_sessions'] = $stmt->fetch()['count'];
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM form_submissions");
    $stmt->execute();
    $data_counts['form_submissions'] = $stmt->fetch()['count'];
    
} catch(Exception $e) {
    $data_counts = [];
}

$csrf_token = generate_csrf_token();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Delete All Data - Subject Allotment System</title>
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
        .danger-card {
            border-left: 5px solid #dc3545;
        }
        .warning-card {
            border-left: 5px solid #ffc107;
        }
        .info-card {
            border-left: 5px solid #17a2b8;
        }
        .delete-option {
            background: #fff;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        .delete-option:hover {
            border-color: #dc3545;
            background: #fff5f5;
        }
        .delete-option.selected {
            border-color: #dc3545;
            background: #fff5f5;
        }
        .danger-zone {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            color: white;
            border-radius: 15px;
            padding: 20px;
            margin: 20px 0;
        }
        .count-badge {
            font-size: 1.2rem;
            font-weight: bold;
        }
        .dependency-info {
            background: #e7f3ff;
            border-left: 4px solid #007bff;
            padding: 10px 15px;
            margin: 10px 0;
            border-radius: 5px;
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
            <h2><i class="fas fa-trash-alt me-2 text-danger"></i>Delete All Data</h2>
            <div class="text-muted">
                <small>Logged in as: <?php echo htmlspecialchars($_SESSION['admin_name']); ?></small>
            </div>
        </div>

        <!-- Warning Alert -->
        <div class="alert alert-danger">
            <h4><i class="fas fa-exclamation-triangle me-2"></i>?? DANGER ZONE ??</h4>
            <p class="mb-0">
                <strong>This page allows you to permanently delete system data.</strong><br>
                All deletion operations are <strong>IRREVERSIBLE</strong>. Make sure you have proper backups before proceeding.
                Database dependencies are automatically handled to prevent errors.
            </p>
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

        <!-- Deletion Results -->
        <?php if (!empty($deletion_results)): ?>
        <div class="card info-card mb-4">
            <div class="card-header bg-info text-white">
                <h5 class="mb-0">
                    <i class="fas fa-chart-bar me-2"></i>Deletion Results
                </h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <?php foreach ($deletion_results as $type => $count): ?>
                    <div class="col-md-3 mb-2">
                        <div class="d-flex justify-content-between align-items-center">
                            <strong><?php echo $type; ?>:</strong>
                            <span class="badge bg-danger count-badge"><?php echo number_format($count); ?></span>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <div class="row">
            <!-- Left Column - Data Counts -->
            <div class="col-lg-4">
                <div class="card info-card">
                    <div class="card-header bg-info text-white">
                        <h5 class="mb-0">
                            <i class="fas fa-database me-2"></i>Current Data Counts
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="list-group list-group-flush">
                            <div class="list-group-item d-flex justify-content-between align-items-center">
                                <div>
                                    <i class="fas fa-layer-group me-2 text-primary"></i>
                                    Subject Pools
                                </div>
                                <span class="badge bg-primary rounded-pill"><?php echo number_format($data_counts['subject_pools'] ?? 0); ?></span>
                            </div>
                            <div class="list-group-item d-flex justify-content-between align-items-center">
                                <div>
                                    <i class="fas fa-users me-2 text-success"></i>
                                    Student Registrations
                                </div>
                                <span class="badge bg-success rounded-pill"><?php echo number_format($data_counts['student_registrations'] ?? 0); ?></span>
                            </div>
                            <div class="list-group-item d-flex justify-content-between align-items-center">
                                <div>
                                    <i class="fas fa-trophy me-2 text-warning"></i>
                                    Subject Allotments
                                </div>
                                <span class="badge bg-warning rounded-pill"><?php echo number_format($data_counts['subject_allotments'] ?? 0); ?></span>
                            </div>
                            <div class="list-group-item d-flex justify-content-between align-items-center">
                                <div>
                                    <i class="fas fa-chart-line me-2 text-info"></i>
                                    Academic Data
                                </div>
                                <span class="badge bg-info rounded-pill"><?php echo number_format($data_counts['academic_data'] ?? 0); ?></span>
                            </div>
                            <div class="list-group-item d-flex justify-content-between align-items-center">
                                <div>
                                    <i class="fas fa-history me-2 text-secondary"></i>
                                    Activity Logs
                                </div>
                                <span class="badge bg-secondary rounded-pill"><?php echo number_format($data_counts['activity_logs'] ?? 0); ?></span>
                            </div>
                            <div class="list-group-item d-flex justify-content-between align-items-center">
                                <div>
                                    <i class="fas fa-sign-in-alt me-2 text-dark"></i>
                                    Login Logs
                                </div>
                                <span class="badge bg-dark rounded-pill"><?php echo number_format($data_counts['login_logs'] ?? 0); ?></span>
                            </div>
                            <div class="list-group-item d-flex justify-content-between align-items-center">
                                <div>
                                    <i class="fas fa-shield-alt me-2 text-danger"></i>
                                    Security Logs
                                </div>
                                <span class="badge bg-danger rounded-pill"><?php echo number_format($data_counts['security_logs'] ?? 0); ?></span>
                            </div>
                            <div class="list-group-item d-flex justify-content-between align-items-center">
                                <div>
                                    <i class="fas fa-clock me-2 text-muted"></i>
                                    Active Sessions
                                </div>
                                <span class="badge bg-light text-dark rounded-pill"><?php echo number_format($data_counts['user_sessions'] ?? 0); ?></span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Right Column - Deletion Options -->
            <div class="col-lg-8">
                <div class="card danger-card">
                    <div class="card-header bg-danger text-white">
                        <h5 class="mb-0">
                            <i class="fas fa-trash-alt me-2"></i>Deletion Options
                        </h5>
                    </div>
                    <div class="card-body">
                        <form method="POST" action="" id="deleteForm">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <input type="hidden" name="form_token" value="<?php echo generate_token(); ?>">
                            <input type="hidden" name="action" id="selectedAction">

                            <div class="delete-option" data-action="delete_allotments">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <h6><i class="fas fa-trophy me-2 text-warning"></i>Delete All Subject Allotments</h6>
                                        <p class="text-muted mb-2">Remove all student subject allotments. Students can be re-allotted later.</p>
                                        <small class="text-success">? Safe operation - No dependencies</small>
                                    </div>
                                    <span class="badge bg-warning"><?php echo number_format($data_counts['subject_allotments'] ?? 0); ?></span>
                                </div>
                            </div>

                            <div class="delete-option" data-action="delete_registrations">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <h6><i class="fas fa-users me-2 text-success"></i>Delete All Student Registrations</h6>
                                        <p class="text-muted mb-2">Remove all student registrations and their allotments.</p>
                                        <div class="dependency-info">
                                            <small><strong>Auto-deletes:</strong> All subject allotments (<?php echo number_format($data_counts['subject_allotments'] ?? 0); ?>)</small>
                                        </div>
                                    </div>
                                    <span class="badge bg-success"><?php echo number_format($data_counts['student_registrations'] ?? 0); ?></span>
                                </div>
                            </div>

                            <div class="delete-option" data-action="delete_academic_data">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <h6><i class="fas fa-chart-line me-2 text-info"></i>Delete All Academic Data</h6>
                                        <p class="text-muted mb-2">Remove all student CGPA and backlog information.</p>
                                        <small class="text-success">? Safe operation - No dependencies</small>
                                    </div>
                                    <span class="badge bg-info"><?php echo number_format($data_counts['academic_data'] ?? 0); ?></span>
                                </div>
                            </div>

                            <div class="delete-option" data-action="delete_subject_pools">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <h6><i class="fas fa-layer-group me-2 text-primary"></i>Deactivate All Subject Pools</h6>
                                        <p class="text-muted mb-2">Deactivate all subject pools and remove related data.</p>
                                        <div class="dependency-info">
                                            <small><strong>Auto-deletes:</strong> All registrations (<?php echo number_format($data_counts['student_registrations'] ?? 0); ?>) and allotments (<?php echo number_format($data_counts['subject_allotments'] ?? 0); ?>)</small>
                                        </div>
                                    </div>
                                    <span class="badge bg-primary"><?php echo number_format($data_counts['subject_pools'] ?? 0); ?></span>
                                </div>
                            </div>

                            <div class="delete-option" data-action="delete_logs">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <h6><i class="fas fa-history me-2 text-secondary"></i>Delete All System Logs</h6>
                                        <p class="text-muted mb-2">Remove activity logs, login logs, and security logs.</p>
                                        <small class="text-warning">?? Will remove audit trail</small>
                                    </div>
                                    <span class="badge bg-secondary"><?php echo number_format(($data_counts['activity_logs'] ?? 0) + ($data_counts['login_logs'] ?? 0) + ($data_counts['security_logs'] ?? 0)); ?></span>
                                </div>
                            </div>

                            <div class="delete-option" data-action="delete_sessions">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <h6><i class="fas fa-clock me-2 text-muted"></i>Delete Sessions & Form Data</h6>
                                        <p class="text-muted mb-2">Remove all user sessions and form submission tracking.</p>
                                        <small class="text-info">?? Users will need to log in again</small>
                                    </div>
                                    <span class="badge bg-light text-dark"><?php echo number_format(($data_counts['user_sessions'] ?? 0) + ($data_counts['form_submissions'] ?? 0)); ?></span>
                                </div>
                            </div>

                            <div class="delete-option" data-action="delete_all_student_data">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <h6><i class="fas fa-user-graduate me-2 text-danger"></i>Delete ALL Student Data</h6>
                                        <p class="text-muted mb-2">Remove everything related to students (preserves subject pools).</p>
                                        <div class="dependency-info">
                                            <small><strong>Deletes:</strong> All registrations, allotments, and academic data</small>
                                        </div>
                                    </div>
                                    <span class="badge bg-danger"><?php echo number_format(($data_counts['student_registrations'] ?? 0) + ($data_counts['subject_allotments'] ?? 0) + ($data_counts['academic_data'] ?? 0)); ?></span>
                                </div>
                            </div>

                            <div class="danger-zone">
                                <div class="delete-option bg-transparent border-white text-white" data-action="reset_all_data">
                                    <div class="d-flex justify-content-between align-items-start">
                                        <div>
                                            <h6><i class="fas fa-bomb me-2"></i>?? NUCLEAR OPTION: Reset Everything ??</h6>
                                            <p class="mb-2">Delete ALL data except admin accounts. Complete system reset.</p>
                                            <small><strong>Deletes:</strong> Everything except admin users</small>
                                        </div>
                                        <span class="badge bg-light text-danger fs-6">TOTAL RESET</span>
                                    </div>
                                </div>
                            </div>

                            <div class="mt-4">
                                <div class="alert alert-warning">
                                    <h6><i class="fas fa-exclamation-triangle me-2"></i>Confirmation Required</h6>
                                    <p class="mb-3">Type <strong>"DELETE ALL"</strong> (without quotes) to confirm the operation:</p>
                                    <input type="text" class="form-control" name="confirm_text" id="confirmText" 
                                           placeholder="Type DELETE ALL to confirm" autocomplete="off">
                                </div>
                                
                                <div class="d-grid">
                                    <button type="submit" class="btn btn-danger btn-lg" id="deleteBtn" disabled>
                                        <i class="fas fa-trash-alt me-2"></i>Execute Deletion
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let selectedAction = '';
        
        // Handle delete option selection
        document.querySelectorAll('.delete-option').forEach(option => {
            option.addEventListener('click', function() {
                // Remove previous selection
                document.querySelectorAll('.delete-option').forEach(opt => opt.classList.remove('selected'));
                
                // Add selection to current option
                this.classList.add('selected');
                
                // Set the action
                selectedAction = this.dataset.action;
                document.getElementById('selectedAction').value = selectedAction;
                
                // Update button text
                const actionTexts = {
                    'delete_allotments': 'Delete All Subject Allotments',
                    'delete_registrations': 'Delete All Student Registrations',
                    'delete_academic_data': 'Delete All Academic Data',
                    'delete_subject_pools': 'Deactivate All Subject Pools',
                    'delete_logs': 'Delete All System Logs',
                    'delete_sessions': 'Delete All Sessions',
                    'delete_all_student_data': 'Delete ALL Student Data',
                    'reset_all_data': '?? RESET EVERYTHING ??'
                };
                
                document.getElementById('deleteBtn').innerHTML = 
                    `<i class="fas fa-trash-alt me-2"></i>${actionTexts[selectedAction] || 'Execute Deletion'}`;
                
                checkFormValidity();
            });
        });
        
        // Handle confirmation text
        document.getElementById('confirmText').addEventListener('input', function() {
            checkFormValidity();
        });
        
        function checkFormValidity() {
            const confirmText = document.getElementById('confirmText').value;
            const deleteBtn = document.getElementById('deleteBtn');
            
            if (selectedAction && confirmText === 'DELETE ALL') {
                deleteBtn.disabled = false;
                deleteBtn.classList.remove('btn-danger');
                deleteBtn.classList.add('btn-outline-danger');
            } else {
                deleteBtn.disabled = true;
                deleteBtn.classList.remove('btn-outline-danger');
                deleteBtn.classList.add('btn-danger');
            }
        }
        
        // Form submission
        document.getElementById('deleteForm').addEventListener('submit', function(e) {
            if (!selectedAction) {
                e.preventDefault();
                alert('Please select a deletion option first.');
                return;
            }
            
            if (document.getElementById('confirmText').value !== 'DELETE ALL') {
                e.preventDefault();
                alert('Please type "DELETE ALL" to confirm the operation.');
                return;
            }
            
            const actionTexts = {
                'delete_allotments': 'delete all subject allotments',
                'delete_registrations': 'delete all student registrations',
                'delete_academic_data': 'delete all academic data',
                'delete_subject_pools': 'deactivate all subject pools',
                'delete_logs': 'delete all system logs',
                'delete_sessions': 'delete all sessions',
                'delete_all_student_data': 'delete ALL student data',
                'reset_all_data': 'RESET THE ENTIRE SYSTEM'
            };
            
            if (!confirm(`Are you absolutely sure you want to ${actionTexts[selectedAction]}?\n\nThis action is IRREVERSIBLE and will be logged.`)) {
                e.preventDefault();
                return;
            }
            
            // Show loading state
            const deleteBtn = document.getElementById('deleteBtn');
            deleteBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Deleting...';
            deleteBtn.disabled = true;
        });
        
        // Prevent accidental form resubmission
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
        
        // Warn before leaving page
        window.addEventListener('beforeunload', function(e) {
            if (document.getElementById('confirmText').value.trim() !== '') {
                e.preventDefault();
                e.returnValue = '';
            }
        });
    </script>
</body>
</html>