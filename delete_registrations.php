<?php
// delete_registrations.php
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
$deleted_count = 0;

// Handle bulk deletion
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        log_security_event($conn, 'csrf_violation', 'high', 'CSRF token validation failed for registration deletion', $_SESSION['admin_username']);
        $error_message = 'Security validation failed. Please try again.';
    } else if (!prevent_resubmit($conn, 'admin', $_SESSION['admin_username'], 'bulk_delete_registrations')) {
        $error_message = 'Operation already in progress. Please refresh the page.';
    } else {
        $action = $_POST['action'];
        
        if ($action == 'delete_selected' && !empty($_POST['selected_registrations'])) {
            $selected_ids = $_POST['selected_registrations'];
            $deleted_count = 0;
            $skipped_count = 0;
            
            try {
                $conn->beginTransaction();
                
                foreach ($selected_ids as $reg_id) {
                    $reg_id = intval($reg_id);
                    
                    // Check if student has allotment
                    $stmt = $conn->prepare("
                        SELECT sr.regno, sr.pool_id, sa.id as allotment_id 
                        FROM student_registrations sr
                        LEFT JOIN subject_allotments sa ON sr.regno = sa.regno AND sr.pool_id = sa.pool_id
                        WHERE sr.id = ?
                    ");
                    $stmt->execute([$reg_id]);
                    $registration = $stmt->fetch();
                    
                    if ($registration) {
                        if ($registration['allotment_id']) {
                            // Has allotment - skip
                            $skipped_count++;
                        } else {
                            // No allotment - safe to delete
                            $stmt = $conn->prepare("DELETE FROM student_registrations WHERE id = ?");
                            $stmt->execute([$reg_id]);
                            $deleted_count++;
                        }
                    }
                }
                
                $conn->commit();
                
                log_activity($conn, 'admin', $_SESSION['admin_username'], 'bulk_registrations_deleted', 'student_registrations', null, null, [
                    'deleted' => $deleted_count,
                    'skipped' => $skipped_count
                ]);
                
                $success_message = "Operation completed: $deleted_count registrations deleted.";
                if ($skipped_count > 0) {
                    $success_message .= " $skipped_count registrations skipped (have allotments).";
                }
                
            } catch(Exception $e) {
                $conn->rollBack();
                error_log("Bulk deletion error: " . $e->getMessage());
                $error_message = 'An error occurred during deletion: ' . $e->getMessage();
            }
        }
        
        // Delete by criteria
        elseif ($action == 'delete_by_criteria') {
            $criteria = $_POST['delete_criteria'] ?? '';
            $pool_id = intval($_POST['pool_id'] ?? 0);
            
            try {
                $conn->beginTransaction();
                $where_conditions = [];
                $params = [];
                
                // Base condition - no allotments
                $base_query = "
                    DELETE sr FROM student_registrations sr
                    LEFT JOIN subject_allotments sa ON sr.regno = sa.regno AND sr.pool_id = sa.pool_id
                    WHERE sa.id IS NULL
                ";
                
                switch ($criteria) {
                    case 'not_frozen':
                        $where_conditions[] = "sr.status = 'saved'";
                        break;
                        
                    case 'no_preferences':
                        $where_conditions[] = "(sr.priority_order IS NULL OR sr.priority_order = '[]')";
                        break;
                        
                    case 'no_academic_data':
                        $base_query = "
                            DELETE sr FROM student_registrations sr
                            LEFT JOIN student_academic_data sad ON sr.regno = sad.regno
                            LEFT JOIN subject_allotments sa ON sr.regno = sa.regno AND sr.pool_id = sa.pool_id
                            WHERE sa.id IS NULL AND sad.id IS NULL
                        ";
                        break;
                        
                    case 'specific_pool':
                        if ($pool_id > 0) {
                            $where_conditions[] = "sr.pool_id = ?";
                            $params[] = $pool_id;
                        }
                        break;
                }
                
                if (!empty($where_conditions)) {
                    $base_query .= " AND " . implode(" AND ", $where_conditions);
                }
                
                $stmt = $conn->prepare($base_query);
                $stmt->execute($params);
                $deleted_count = $stmt->rowCount();
                
                $conn->commit();
                
                log_activity($conn, 'admin', $_SESSION['admin_username'], 'criteria_based_deletion', 'student_registrations', null, null, [
                    'criteria' => $criteria,
                    'deleted' => $deleted_count
                ]);
                
                $success_message = "$deleted_count registrations deleted based on selected criteria.";
                
            } catch(Exception $e) {
                $conn->rollBack();
                error_log("Criteria deletion error: " . $e->getMessage());
                $error_message = 'An error occurred during deletion: ' . $e->getMessage();
            }
        }
    }
}

// Get filters
$filter_pool = intval($_GET['pool'] ?? 0);
$filter_status = $_GET['status'] ?? '';
$filter_has_academic = $_GET['academic'] ?? '';
$filter_has_allotment = $_GET['allotment'] ?? '';
$search = trim($_GET['search'] ?? '');

// Build query
$where_conditions = ['1=1'];
$params = [];

if ($filter_pool > 0) {
    $where_conditions[] = 'sr.pool_id = ?';
    $params[] = $filter_pool;
}

if ($filter_status) {
    $where_conditions[] = 'sr.status = ?';
    $params[] = $filter_status;
}

if ($filter_has_academic === '1') {
    $where_conditions[] = 'sad.id IS NOT NULL';
} elseif ($filter_has_academic === '0') {
    $where_conditions[] = 'sad.id IS NULL';
}

if ($filter_has_allotment === '1') {
    $where_conditions[] = 'sa.id IS NOT NULL';
} elseif ($filter_has_allotment === '0') {
    $where_conditions[] = 'sa.id IS NULL';
}

if ($search) {
    $where_conditions[] = '(sr.regno LIKE ? OR sr.email LIKE ?)';
    $params[] = "%$search%";
    $params[] = "%$search%";
}

$where_clause = implode(' AND ', $where_conditions);

// Get registrations
try {
    $stmt = $conn->prepare("
        SELECT 
            sr.*,
            sp.pool_name,
            sp.subject_name,
            sp.semester,
            sp.batch,
            sad.cgpa,
            sad.backlogs,
            sa.subject_code as allotted_subject,
            CASE 
                WHEN sr.priority_order IS NULL OR sr.priority_order = '[]' THEN 0
                ELSE JSON_LENGTH(sr.priority_order)
            END as preference_count
        FROM student_registrations sr
        JOIN subject_pools sp ON sr.pool_id = sp.id
        LEFT JOIN student_academic_data sad ON sr.regno = sad.regno
        LEFT JOIN subject_allotments sa ON sr.regno = sa.regno AND sr.pool_id = sa.pool_id
        WHERE $where_clause
        ORDER BY sr.registered_at DESC
    ");
    $stmt->execute($params);
    $registrations = $stmt->fetchAll();
    
    // Get pools for filter
    $stmt = $conn->prepare("
        SELECT DISTINCT sp.id, sp.pool_name, sp.semester, sp.batch
        FROM subject_pools sp
        WHERE sp.is_active = 1
        ORDER BY sp.pool_name
    ");
    $stmt->execute();
    $pools = $stmt->fetchAll();
    
    // Get statistics
    $stmt = $conn->query("SELECT COUNT(*) FROM student_registrations");
    $total_registrations = $stmt->fetchColumn();
    
    $stmt = $conn->query("
        SELECT COUNT(*) FROM student_registrations sr
        LEFT JOIN subject_allotments sa ON sr.regno = sa.regno AND sr.pool_id = sa.pool_id
        WHERE sa.id IS NULL
    ");
    $deletable_registrations = $stmt->fetchColumn();
    
} catch(Exception $e) {
    error_log("Query error: " . $e->getMessage());
    $registrations = [];
    $pools = [];
}

$csrf_token = generate_csrf_token();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Delete Student Registrations - Subject Allotment System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .card { border: none; border-radius: 15px; box-shadow: 0 0 20px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .danger-zone { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; padding: 20px; border-radius: 10px; }
        .table-container { max-height: 600px; overflow-y: auto; }
        .deletable { background-color: #fff3cd; }
        .has-allotment { background-color: #f8d7da; }
        .stat-box { text-align: center; padding: 20px; background: white; border-radius: 10px; margin-bottom: 15px; }
        .stat-number { font-size: 2rem; font-weight: bold; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="admin_dashboard.php">
                <i class="fas fa-graduation-cap me-2"></i>Subject Allotment System
            </a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="student_registrations.php">
                    <i class="fas fa-arrow-left me-1"></i>Back to Registrations
                </a>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <div class="danger-zone mb-4">
            <h2><i class="fas fa-trash-alt me-2"></i>Delete Student Registrations</h2>
            <p class="mb-0">⚠️ <strong>WARNING:</strong> This page allows bulk deletion of student registrations. Registrations with allotments cannot be deleted.</p>
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

        <!-- Statistics -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-number text-primary"><?php echo $total_registrations; ?></div>
                    <div class="text-muted">Total Registrations</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-number text-success"><?php echo $deletable_registrations; ?></div>
                    <div class="text-muted">Deletable (No Allotment)</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-number text-danger"><?php echo $total_registrations - $deletable_registrations; ?></div>
                    <div class="text-muted">Protected (Has Allotment)</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-number text-warning"><?php echo count($registrations); ?></div>
                    <div class="text-muted">Filtered Results</div>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Filters -->
            <div class="col-lg-4">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h5 class="mb-0"><i class="fas fa-filter me-2"></i>Filters</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET" action="">
                            <div class="mb-3">
                                <label for="pool" class="form-label">Subject Pool</label>
                                <select class="form-select" id="pool" name="pool">
                                    <option value="">All Pools</option>
                                    <?php foreach ($pools as $pool): ?>
                                        <option value="<?php echo $pool['id']; ?>" <?php echo $filter_pool == $pool['id'] ? 'selected' : ''; ?>>
                                            <?php echo htmlspecialchars($pool['pool_name'] . ' - ' . $pool['semester']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            
                            <div class="mb-3">
                                <label for="status" class="form-label">Status</label>
                                <select class="form-select" id="status" name="status">
                                    <option value="">All Status</option>
                                    <option value="saved" <?php echo $filter_status == 'saved' ? 'selected' : ''; ?>>Saved</option>
                                    <option value="frozen" <?php echo $filter_status == 'frozen' ? 'selected' : ''; ?>>Frozen</option>
                                </select>
                            </div>
                            
                            <div class="mb-3">
                                <label for="academic" class="form-label">Academic Data</label>
                                <select class="form-select" id="academic" name="academic">
                                    <option value="">All</option>
                                    <option value="1" <?php echo $filter_has_academic == '1' ? 'selected' : ''; ?>>Has Academic Data</option>
                                    <option value="0" <?php echo $filter_has_academic == '0' ? 'selected' : ''; ?>>No Academic Data</option>
                                </select>
                            </div>
                            
                            <div class="mb-3">
                                <label for="allotment" class="form-label">Allotment Status</label>
                                <select class="form-select" id="allotment" name="allotment">
                                    <option value="">All</option>
                                    <option value="1" <?php echo $filter_has_allotment == '1' ? 'selected' : ''; ?>>Has Allotment</option>
                                    <option value="0" <?php echo $filter_has_allotment == '0' ? 'selected' : ''; ?>>No Allotment</option>
                                </select>
                            </div>
                            
                            <div class="mb-3">
                                <label for="search" class="form-label">Search</label>
                                <input type="text" class="form-control" id="search" name="search" 
                                       placeholder="Registration No or Email" value="<?php echo htmlspecialchars($search); ?>">
                            </div>
                            
                            <div class="d-grid gap-2">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-search me-2"></i>Apply Filters
                                </button>
                                <a href="delete_registrations.php" class="btn btn-secondary">
                                    <i class="fas fa-times me-2"></i>Clear Filters
                                </a>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Bulk Delete Options -->
                <div class="card mt-4">
                    <div class="card-header bg-danger text-white">
                        <h5 class="mb-0"><i class="fas fa-trash-alt me-2"></i>Bulk Delete Options</h5>
                    </div>
                    <div class="card-body">
                        <form method="POST" action="" onsubmit="return confirmBulkDelete(this)">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <input type="hidden" name="form_token" value="<?php echo generate_token(); ?>">
                            <input type="hidden" name="action" value="delete_by_criteria">
                            
                            <div class="mb-3">
                                <label for="delete_criteria" class="form-label">Delete by Criteria</label>
                                <select class="form-select" id="delete_criteria" name="delete_criteria" required>
                                    <option value="">Select criteria...</option>
                                    <option value="not_frozen">Not Frozen (Status = Saved)</option>
                                    <option value="no_preferences">No Preferences Set</option>
                                    <option value="no_academic_data">No Academic Data</option>
                                    <option value="specific_pool">Specific Pool (select below)</option>
                                </select>
                            </div>
                            
                            <div class="mb-3" id="poolSelectDiv" style="display: none;">
                                <label for="pool_id" class="form-label">Select Pool</label>
                                <select class="form-select" id="pool_id" name="pool_id">
                                    <option value="">Select pool...</option>
                                    <?php foreach ($pools as $pool): ?>
                                        <option value="<?php echo $pool['id']; ?>">
                                            <?php echo htmlspecialchars($pool['pool_name'] . ' - ' . $pool['semester']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            
                            <div class="alert alert-warning">
                                <i class="fas fa-exclamation-triangle me-2"></i>
                                Only registrations without allotments will be deleted.
                            </div>
                            
                            <div class="d-grid">
                                <button type="submit" class="btn btn-danger">
                                    <i class="fas fa-trash-alt me-2"></i>Delete by Criteria
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Registration List -->
            <div class="col-lg-8">
                <form method="POST" action="" id="bulkDeleteForm">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="form_token" value="<?php echo generate_token(); ?>">
                    <input type="hidden" name="action" value="delete_selected">
                    
                    <div class="card">
                        <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                            <h5 class="mb-0">
                                <i class="fas fa-list me-2"></i>Student Registrations
                            </h5>
                            <div>
                                <button type="button" class="btn btn-outline-light btn-sm" onclick="selectAll()">
                                    <i class="fas fa-check-square me-1"></i>Select All Deletable
                                </button>
                                <button type="button" class="btn btn-outline-light btn-sm" onclick="clearSelection()">
                                    <i class="fas fa-square me-1"></i>Clear
                                </button>
                                <button type="submit" class="btn btn-danger btn-sm" onclick="return confirmSelectedDelete()">
                                    <i class="fas fa-trash me-1"></i>Delete Selected
                                </button>
                            </div>
                        </div>
                        <div class="card-body p-0">
                            <div class="table-responsive table-container">
                                <table class="table table-hover mb-0">
                                    <thead class="table-light sticky-top">
                                        <tr>
                                            <th width="40"></th>
                                            <th>Reg No</th>
                                            <th>Email</th>
                                            <th>Pool</th>
                                            <th>Status</th>
                                            <th>Preferences</th>
                                            <th>Academic</th>
                                            <th>Allotment</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($registrations as $reg): ?>
                                        <tr class="<?php echo $reg['allotted_subject'] ? 'has-allotment' : 'deletable'; ?>">
                                            <td>
                                                <?php if (!$reg['allotted_subject']): ?>
                                                    <input type="checkbox" class="form-check-input" name="selected_registrations[]" 
                                                           value="<?php echo $reg['id']; ?>">
                                                <?php else: ?>
                                                    <i class="fas fa-lock text-danger" title="Has allotment - cannot delete"></i>
                                                <?php endif; ?>
                                            </td>
                                            <td><strong><?php echo htmlspecialchars($reg['regno']); ?></strong></td>
                                            <td><small><?php echo htmlspecialchars($reg['email']); ?></small></td>
                                            <td>
                                                <small>
                                                    <?php echo htmlspecialchars($reg['pool_name']); ?><br>
                                                    <?php echo htmlspecialchars($reg['semester']); ?>
                                                </small>
                                            </td>
                                            <td>
                                                <span class="badge bg-<?php echo $reg['status'] == 'frozen' ? 'danger' : 'warning'; ?>">
                                                    <?php echo ucfirst($reg['status']); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <span class="badge bg-info"><?php echo $reg['preference_count']; ?></span>
                                            </td>
                                            <td>
                                                <?php if ($reg['cgpa'] !== null || $reg['backlogs'] !== null): ?>
                                                    <i class="fas fa-check text-success"></i>
                                                <?php else: ?>
                                                    <i class="fas fa-times text-danger"></i>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <?php if ($reg['allotted_subject']): ?>
                                                    <span class="badge bg-success"><?php echo htmlspecialchars($reg['allotted_subject']); ?></span>
                                                <?php else: ?>
                                                    <span class="text-muted">None</span>
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
    <script>
        // Show/hide pool selection based on criteria
        document.getElementById('delete_criteria').addEventListener('change', function() {
            document.getElementById('poolSelectDiv').style.display = 
                this.value === 'specific_pool' ? 'block' : 'none';
        });

        function selectAll() {
            document.querySelectorAll('input[name="selected_registrations[]"]').forEach(cb => cb.checked = true);
        }

        function clearSelection() {
            document.querySelectorAll('input[name="selected_registrations[]"]').forEach(cb => cb.checked = false);
        }

        function confirmSelectedDelete() {
            const selected = document.querySelectorAll('input[name="selected_registrations[]"]:checked').length;
            if (selected === 0) {
                alert('Please select at least one registration to delete.');
                return false;
            }
            return confirm(`Are you sure you want to delete ${selected} registration(s)? This cannot be undone.`);
        }

        function confirmBulkDelete(form) {
            const criteria = form.delete_criteria.value;
            if (!criteria) {
                alert('Please select a deletion criteria.');
                return false;
            }
            return confirm('Are you sure you want to delete registrations based on the selected criteria? This cannot be undone.');
        }
    </script>
</body>
</html>