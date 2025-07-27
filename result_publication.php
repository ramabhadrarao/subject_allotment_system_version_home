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

// Handle result publication actions
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        log_security_event($conn, 'csrf_violation', 'high', 'CSRF token validation failed for result publication', $_SESSION['admin_username']);
        $error_message = 'Security validation failed. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';
        
        // Publish Results
        if ($action == 'publish_results' && prevent_resubmit($conn, 'admin', $_SESSION['admin_username'], 'publish_results')) {
            $pool_id = intval($_POST['pool_id'] ?? 0);
            
            if ($pool_id <= 0) {
                $error_message = 'Please select a valid pool.';
            } else {
                try {
                    // Get pool information
                    $stmt = $conn->prepare("SELECT pool_name FROM subject_pools WHERE id = ?");
                    $stmt->execute([$pool_id]);
                    $pool_info = $stmt->fetch();
                    
                    if (!$pool_info) {
                        $error_message = 'Pool not found.';
                    } else {
                        // Check if results exist for this pool
                        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM subject_allotments WHERE pool_id = ?");
                        $stmt->execute([$pool_id]);
                        $allotment_count = $stmt->fetch()['count'];
                        
                        if ($allotment_count == 0) {
                            $error_message = 'No allotment results found for this pool. Please run allotment first.';
                        } else {
                            // Check if already published
                            $stmt = $conn->prepare("SELECT * FROM result_publication WHERE pool_id = ?");
                            $stmt->execute([$pool_id]);
                            $existing_publication = $stmt->fetch();
                            
                            if ($existing_publication && $existing_publication['results_published'] == 1) {
                                $error_message = 'Results for this pool are already published.';
                            } else {
                                $conn->beginTransaction();
                                
                                if ($existing_publication) {
                                    // Update existing record
                                    $stmt = $conn->prepare("UPDATE result_publication SET results_published = 1, published_at = NOW(), published_by = ? WHERE pool_id = ?");
                                    $stmt->execute([$_SESSION['admin_id'], $pool_id]);
                                } else {
                                    // Insert new record
                                    $stmt = $conn->prepare("INSERT INTO result_publication (pool_id, pool_name, results_published, published_at, published_by) VALUES (?, ?, 1, NOW(), ?)");
                                    $stmt->execute([$pool_id, $pool_info['pool_name'], $_SESSION['admin_id']]);
                                }
                                
                                $conn->commit();
                                
                                log_activity($conn, 'admin', $_SESSION['admin_username'], 'results_published', 'result_publication', $pool_id, null, [
                                    'pool_name' => $pool_info['pool_name'],
                                    'allotment_count' => $allotment_count
                                ]);
                                
                                $success_message = "Results published successfully for {$pool_info['pool_name']}! Students can now view their allotment results.";
                            }
                        }
                    }
                } catch(Exception $e) {
                    if ($conn->inTransaction()) {
                        $conn->rollBack();
                    }
                    error_log("Result publication error: " . $e->getMessage());
                    $error_message = 'An error occurred while publishing results: ' . $e->getMessage();
                }
            }
        }
        
        // Unpublish Results
        elseif ($action == 'unpublish_results' && prevent_resubmit($conn, 'admin', $_SESSION['admin_username'], 'unpublish_results')) {
            $pool_id = intval($_POST['pool_id'] ?? 0);
            
            if ($pool_id <= 0) {
                $error_message = 'Please select a valid pool.';
            } else {
                try {
                    $stmt = $conn->prepare("UPDATE result_publication SET results_published = 0, published_at = NULL, published_by = NULL WHERE pool_id = ?");
                    $stmt->execute([$pool_id]);
                    
                    if ($stmt->rowCount() > 0) {
                        log_activity($conn, 'admin', $_SESSION['admin_username'], 'results_unpublished', 'result_publication', $pool_id);
                        $success_message = 'Results unpublished successfully! Students can no longer view results for this pool.';
                    } else {
                        $error_message = 'No publication record found for this pool.';
                    }
                } catch(Exception $e) {
                    error_log("Result unpublish error: " . $e->getMessage());
                    $error_message = 'An error occurred while unpublishing results.';
                }
            }
        }
    }
}

// Get pools with allotment results
try {
    $stmt = $conn->prepare("
        SELECT 
            sp.id,
            sp.pool_name,
            sp.semester,
            sp.batch,
            COUNT(DISTINCT sa.regno) as allotted_students,
            COUNT(DISTINCT sr.regno) as registered_students,
            rp.results_published,
            rp.published_at,
            rp.published_by,
            a.name as published_by_name
        FROM subject_pools sp
        LEFT JOIN subject_allotments sa ON sp.id = sa.pool_id
        LEFT JOIN student_registrations sr ON sp.id = sr.pool_id
        LEFT JOIN result_publication rp ON sp.id = rp.pool_id
        LEFT JOIN admin a ON rp.published_by = a.id
        WHERE sp.is_active = 1
        GROUP BY sp.id, sp.pool_name, sp.semester, sp.batch
        HAVING allotted_students > 0
        ORDER BY rp.results_published ASC, sp.pool_name
    ");
    $stmt->execute();
    $pools_with_results = $stmt->fetchAll();
    
    // Get overall statistics
    $stmt = $conn->prepare("SELECT COUNT(*) as published_pools FROM result_publication WHERE results_published = 1");
    $stmt->execute();
    $published_pools_count = $stmt->fetch()['published_pools'];
    
    $stmt = $conn->prepare("SELECT COUNT(DISTINCT pool_id) as total_pools_with_results FROM subject_allotments");
    $stmt->execute();
    $total_pools_with_results = $stmt->fetch()['total_pools_with_results'];
    
} catch(Exception $e) {
    error_log("Result publication query error: " . $e->getMessage());
    $pools_with_results = [];
    $published_pools_count = 0;
    $total_pools_with_results = 0;
}

$csrf_token = generate_csrf_token();
log_activity($conn, 'admin', $_SESSION['admin_username'], 'result_publication_page_viewed');
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Result Publication Management - Subject Allotment System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .stats-card {
            border-left: 5px solid #007bff;
        }
        .publication-card {
            border-left: 5px solid #28a745;
        }
        .published-row {
            background-color: #d4edda;
        }
        .unpublished-row {
            background-color: #fff3cd;
        }
        .stat-item {
            text-align: center;
            padding: 1.5rem;
        }
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        .publication-badge {
            font-size: 0.85rem;
            padding: 0.5rem 1rem;
        }
        .action-buttons .btn {
            margin: 2px;
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
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-circle me-1"></i>
                            <?php echo htmlspecialchars($_SESSION['admin_name']); ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="admin_dashboard.php">
                                <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                            </a></li>
                            <li><a class="dropdown-item" href="allotment_results.php">
                                <i class="fas fa-list-alt me-2"></i>View Results
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="admin_logout.php">
                                <i class="fas fa-sign-out-alt me-2"></i>Logout
                            </a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2><i class="fas fa-bullhorn me-2"></i>Result Publication Management</h2>
            <div class="text-muted">
                <small>Control when students can view their allotment results</small>
            </div>
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

        <!-- Statistics Row -->
        <div class="row mb-4">
            <div class="col-lg-4 col-md-6 mb-3">
                <div class="card stats-card h-100">
                    <div class="card-body stat-item">
                        <div class="stat-number text-primary"><?php echo $total_pools_with_results; ?></div>
                        <div class="text-muted">Pools with Results</div>
                    </div>
                </div>
            </div>
            <div class="col-lg-4 col-md-6 mb-3">
                <div class="card stats-card h-100">
                    <div class="card-body stat-item">
                        <div class="stat-number text-success"><?php echo $published_pools_count; ?></div>
                        <div class="text-muted">Published Pools</div>
                    </div>
                </div>
            </div>
            <div class="col-lg-4 col-md-6 mb-3">
                <div class="card stats-card h-100">
                    <div class="card-body stat-item">
                        <div class="stat-number text-warning"><?php echo ($total_pools_with_results - $published_pools_count); ?></div>
                        <div class="text-muted">Pending Publication</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Publication Control Panel -->
        <div class="card publication-card">
            <div class="card-header bg-success text-white">
                <h5 class="mb-0">
                    <i class="fas fa-cog me-2"></i>Publication Control Panel
                </h5>
            </div>
            <div class="card-body">
                <?php if (empty($pools_with_results)): ?>
                    <div class="text-center py-5">
                        <i class="fas fa-info-circle fa-4x text-muted mb-3"></i>
                        <h5 class="text-muted">No Results Available for Publication</h5>
                        <p class="text-muted">
                            Run the allotment process first to generate results that can be published to students.
                        </p>
                        <a href="run_allotment.php" class="btn btn-primary">
                            <i class="fas fa-cogs me-2"></i>Run Allotment
                        </a>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-hover" id="publicationTable">
                            <thead class="table-light">
                                <tr>
                                    <th>Pool Name</th>
                                    <th>Semester/Batch</th>
                                    <th>Students</th>
                                    <th>Publication Status</th>
                                    <th>Published Details</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($pools_with_results as $pool): ?>
                                <tr class="<?php echo $pool['results_published'] ? 'published-row' : 'unpublished-row'; ?>">
                                    <td>
                                        <strong><?php echo htmlspecialchars($pool['pool_name']); ?></strong>
                                    </td>
                                    <td>
                                        <div class="small">
                                            <strong><?php echo htmlspecialchars($pool['semester']); ?></strong><br>
                                            <span class="text-muted"><?php echo htmlspecialchars($pool['batch']); ?></span>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="small">
                                            <span class="badge bg-success"><?php echo $pool['allotted_students']; ?> Allotted</span><br>
                                            <span class="badge bg-info"><?php echo $pool['registered_students']; ?> Registered</span>
                                        </div>
                                    </td>
                                    <td>
                                        <?php if ($pool['results_published']): ?>
                                            <span class="badge bg-success publication-badge">
                                                <i class="fas fa-check-circle me-1"></i>PUBLISHED
                                            </span>
                                        <?php else: ?>
                                            <span class="badge bg-warning publication-badge">
                                                <i class="fas fa-clock me-1"></i>NOT PUBLISHED
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($pool['results_published'] && $pool['published_at']): ?>
                                            <div class="small">
                                                <strong>Published:</strong> <?php echo date('M j, Y h:i A', strtotime($pool['published_at'])); ?><br>
                                                <strong>By:</strong> <?php echo htmlspecialchars($pool['published_by_name']); ?>
                                            </div>
                                        <?php else: ?>
                                            <span class="text-muted small">Not published yet</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <div class="action-buttons">
                                            <?php if ($pool['results_published']): ?>
                                                <button type="button" class="btn btn-sm btn-outline-danger" 
                                                        onclick="unpublishResults(<?php echo $pool['id']; ?>, '<?php echo htmlspecialchars($pool['pool_name']); ?>')">
                                                    <i class="fas fa-eye-slash me-1"></i>Unpublish
                                                </button>
                                            <?php else: ?>
                                                <button type="button" class="btn btn-sm btn-outline-success" 
                                                        onclick="publishResults(<?php echo $pool['id']; ?>, '<?php echo htmlspecialchars($pool['pool_name']); ?>')">
                                                    <i class="fas fa-bullhorn me-1"></i>Publish
                                                </button>
                                            <?php endif; ?>
                                            <a href="allotment_results.php?pool=<?php echo $pool['id']; ?>" 
                                               class="btn btn-sm btn-outline-info">
                                                <i class="fas fa-eye me-1"></i>View
                                            </a>
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

    <!-- Publish Confirmation Modal -->
    <div class="modal fade" id="publishModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-bullhorn me-2"></i>Publish Results
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        <strong>Publishing results will make them visible to students.</strong>
                    </div>
                    <p>Are you sure you want to publish results for "<span id="publishPoolName"></span>"?</p>
                    <div class="alert alert-warning">
                        <strong>After publication:</strong>
                        <ul class="mb-0 mt-2">
                            <li>Students will be able to view their allotment results</li>
                            <li>Student dashboard will show allotted subjects</li>
                            <li>You can unpublish later if needed</li>
                        </ul>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <form method="POST" action="" style="display: inline;">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <input type="hidden" name="form_token" value="<?php echo generate_token(); ?>">
                        <input type="hidden" name="action" value="publish_results">
                        <input type="hidden" name="pool_id" id="publishPoolId">
                        <button type="submit" class="btn btn-success">
                            <i class="fas fa-bullhorn me-2"></i>Yes, Publish Results
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Unpublish Confirmation Modal -->
    <div class="modal fade" id="unpublishModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-eye-slash me-2"></i>Unpublish Results
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        <strong>Unpublishing will hide results from students.</strong>
                    </div>
                    <p>Are you sure you want to unpublish results for "<span id="unpublishPoolName"></span>"?</p>
                    <div class="alert alert-info">
                        <strong>After unpublishing:</strong>
                        <ul class="mb-0 mt-2">
                            <li>Students will no longer see their allotment results</li>
                            <li>Student dashboard will not show allotted subjects</li>
                            <li>You can publish again later</li>
                        </ul>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <form method="POST" action="" style="display: inline;">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <input type="hidden" name="form_token" value="<?php echo generate_token(); ?>">
                        <input type="hidden" name="action" value="unpublish_results">
                        <input type="hidden" name="pool_id" id="unpublishPoolId">
                        <button type="submit" class="btn btn-danger">
                            <i class="fas fa-eye-slash me-2"></i>Yes, Unpublish Results
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
    <script>
        $(document).ready(function() {
            $('#publicationTable').DataTable({
                responsive: true,
                pageLength: 10,
                order: [[3, 'asc']], // Sort by publication status
                columnDefs: [
                    { targets: [-1], orderable: false } // Disable sorting for Actions column
                ]
            });
        });

        function publishResults(poolId, poolName) {
            document.getElementById('publishPoolId').value = poolId;
            document.getElementById('publishPoolName').textContent = poolName;
            
            const modal = new bootstrap.Modal(document.getElementById('publishModal'));
            modal.show();
        }

        function unpublishResults(poolId, poolName) {
            document.getElementById('unpublishPoolId').value = poolId;
            document.getElementById('unpublishPoolName').textContent = poolName;
            
            const modal = new bootstrap.Modal(document.getElementById('unpublishModal'));
            modal.show();
        }

        // Prevent form resubmission on page refresh
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
    </script>
</body>
</html>