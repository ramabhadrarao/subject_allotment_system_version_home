<?php
require_once 'dbconfig.php';

// Check admin authentication
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header("Location: admin_login.php");
    exit();
}

// Get filter parameters
$batch_filter = $_GET['batch'] ?? '';
$programme_filter = $_GET['programme'] ?? '';
$status_filter = $_GET['status'] ?? '';
$pool_filter = intval($_GET['pool'] ?? 0);

// Handle CSV export
if (isset($_GET['export']) && $_GET['export'] == 'csv') {
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="registration_details_report_' . date('Y-m-d') . '.csv"');
    
    $output = fopen('php://output', 'w');
    
    // CSV headers
    fputcsv($output, ['Registration No', 'Student Name', 'Email', 'Mobile', 'Programme', 'Batch', 'Semester', 'Pool Name', 'All Subject Preferences', 'Status', 'Frozen Date', 'CGPA', 'Backlogs', 'Allotted Subject', 'Registration Date']);
    
    // Build query
    $query = "
        SELECT 
            sr.*,
            sp.pool_name,
            sp.semester as pool_semester,
            sp.batch as pool_batch,
            sad.cgpa,
            sad.backlogs,
            sa.subject_code as allotted_subject
        FROM student_registrations sr
        JOIN subject_pools sp ON sr.pool_id = sp.id
        LEFT JOIN student_academic_data sad ON sr.regno = sad.regno
        LEFT JOIN subject_allotments sa ON sr.regno = sa.regno AND sr.pool_id = sa.pool_id
        WHERE 1=1
    ";
    
    $params = [];
    
    if ($pool_filter > 0) {
        $query .= " AND sr.pool_id = ?";
        $params[] = $pool_filter;
    }
    
    if ($status_filter) {
        $query .= " AND sr.status = ?";
        $params[] = $status_filter;
    }
    
    $query .= " ORDER BY sr.pool_id, sr.status DESC, sr.frozen_at DESC";
    
    $stmt = $conn->prepare($query);
    $stmt->execute($params);
    
    while ($reg = $stmt->fetch()) {
        // Get student details from attendance database
        $student_name = $programme = $batch = $semester = '';
        
        if ($attendance_conn) {
            $student_stmt = $attendance_conn->prepare("SELECT name, programme, batch, semester FROM user WHERE regid = ?");
            $student_stmt->execute([$reg['regno']]);
            $student_data = $student_stmt->fetch();
            
            if ($student_data) {
                $student_name = $student_data['name'];
                $programme = $student_data['programme'];
                $batch = $student_data['batch'];
                $semester = $student_data['semester'];
                
                // Apply filters
                if ($batch_filter && $batch != $batch_filter) continue;
                if ($programme_filter && $programme != $programme_filter) continue;
            }
        }
        
        // Format preferences
        $all_preferences = '';
        if ($reg['priority_order']) {
            $priorities = json_decode($reg['priority_order'], true);
            if ($priorities) {
                usort($priorities, function($a, $b) { return $a['priority'] - $b['priority']; });
                
                // Get subject names
                foreach ($priorities as $pref) {
                    $subj_stmt = $conn->prepare("SELECT subject_name FROM subject_pools WHERE subject_code = ? LIMIT 1");
                    $subj_stmt->execute([$pref['subject_code']]);
                    $subject = $subj_stmt->fetch();
                    
                    $all_preferences .= $pref['priority'] . '. ' . $pref['subject_code'];
                    if ($subject) {
                        $all_preferences .= ' - ' . $subject['subject_name'];
                    }
                    $all_preferences .= '; ';
                }
            }
        }
        
        // Get allotted subject name
        $allotted_subject_name = '';
        if ($reg['allotted_subject']) {
            $subj_stmt = $conn->prepare("SELECT subject_name FROM subject_pools WHERE subject_code = ? LIMIT 1");
            $subj_stmt->execute([$reg['allotted_subject']]);
            $subject = $subj_stmt->fetch();
            if ($subject) {
                $allotted_subject_name = $reg['allotted_subject'] . ' - ' . $subject['subject_name'];
            }
        }
        
        fputcsv($output, [
            $reg['regno'],
            $student_name,
            $reg['email'],
            $reg['mobile'],
            $programme,
            $batch,
            $semester,
            $reg['pool_name'],
            $all_preferences,
            ucfirst($reg['status']),
            $reg['frozen_at'] ?? '-',
            $reg['cgpa'] ?? '-',
            $reg['backlogs'] ?? '0',
            $allotted_subject_name ?: 'Not Allotted',
            $reg['registered_at']
        ]);
    }
    
    fclose($output);
    exit();
}

// Get report data
$registration_data = [];
$pool_statistics = [];

try {
    // Get pools for filter
    $stmt = $conn->query("
        SELECT DISTINCT sp.id, sp.pool_name, sp.semester, sp.batch,
        COUNT(DISTINCT sr.regno) as registrations
        FROM subject_pools sp
        LEFT JOIN student_registrations sr ON sp.id = sr.pool_id
        WHERE sp.is_active = 1
        GROUP BY sp.id, sp.pool_name, sp.semester, sp.batch
        ORDER BY sp.pool_name
    ");
    $pools = $stmt->fetchAll();
    
    // Build main query
    $query = "
        SELECT 
            sr.*,
            sp.pool_name,
            sp.semester as pool_semester,
            sp.batch as pool_batch,
            sad.cgpa,
            sad.backlogs,
            sa.subject_code as allotted_subject,
            COUNT(DISTINCT sr2.regno) OVER (PARTITION BY sr.pool_id) as pool_total_registrations,
            COUNT(DISTINCT CASE WHEN sr2.status = 'frozen' THEN sr2.regno END) OVER (PARTITION BY sr.pool_id) as pool_frozen_count
        FROM student_registrations sr
        JOIN subject_pools sp ON sr.pool_id = sp.id
        LEFT JOIN student_academic_data sad ON sr.regno = sad.regno
        LEFT JOIN subject_allotments sa ON sr.regno = sa.regno AND sr.pool_id = sa.pool_id
        LEFT JOIN student_registrations sr2 ON sr.pool_id = sr2.pool_id
        WHERE 1=1
    ";
    
    $params = [];
    
    if ($pool_filter > 0) {
        $query .= " AND sr.pool_id = ?";
        $params[] = $pool_filter;
    }
    
    if ($status_filter) {
        $query .= " AND sr.status = ?";
        $params[] = $status_filter;
    }
    
    $query .= " GROUP BY sr.id ORDER BY sr.pool_id, sr.status DESC, sr.frozen_at DESC";
    
    $stmt = $conn->prepare($query);
    $stmt->execute($params);
    $registrations = $stmt->fetchAll();
    
    // Get student details and apply filters
    foreach ($registrations as $reg) {
        $student_data = ['name' => '', 'programme' => '', 'batch' => '', 'semester' => ''];
        
        if ($attendance_conn) {
            $student_stmt = $attendance_conn->prepare("SELECT name, programme, batch, semester FROM user WHERE regid = ?");
            $student_stmt->execute([$reg['regno']]);
            $student_info = $student_stmt->fetch();
            
            if ($student_info) {
                $student_data = $student_info;
                
                // Apply filters
                if ($batch_filter && $student_info['batch'] != $batch_filter) continue;
                if ($programme_filter && $student_info['programme'] != $programme_filter) continue;
            }
        }
        
        // Merge data
        $registration_data[] = array_merge($reg, $student_data);
        
        // Collect pool statistics
        $pool_key = $reg['pool_id'];
        if (!isset($pool_statistics[$pool_key])) {
            $pool_statistics[$pool_key] = [
                'pool_name' => $reg['pool_name'],
                'total' => 0,
                'frozen' => 0,
                'allotted' => 0,
                'subjects' => []
            ];
        }
        
        $pool_statistics[$pool_key]['total']++;
        if ($reg['status'] == 'frozen') {
            $pool_statistics[$pool_key]['frozen']++;
        }
        if ($reg['allotted_subject']) {
            $pool_statistics[$pool_key]['allotted']++;
        }
        
        // Collect subject preferences
        if ($reg['priority_order']) {
            $priorities = json_decode($reg['priority_order'], true);
            if ($priorities) {
                foreach ($priorities as $pref) {
                    if (!isset($pool_statistics[$pool_key]['subjects'][$pref['subject_code']])) {
                        $pool_statistics[$pool_key]['subjects'][$pref['subject_code']] = 0;
                    }
                    $pool_statistics[$pool_key]['subjects'][$pref['subject_code']]++;
                }
            }
        }
    }
    
    // Get filter options from attendance database
    $batches = [];
    $programmes = [];
    
    if ($attendance_conn) {
        $stmt = $attendance_conn->query("SELECT DISTINCT batch FROM user WHERE batch IS NOT NULL ORDER BY batch DESC");
        $batches = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        $stmt = $attendance_conn->query("SELECT DISTINCT programme FROM user WHERE programme IS NOT NULL ORDER BY programme");
        $programmes = $stmt->fetchAll(PDO::FETCH_COLUMN);
    }
    
} catch(Exception $e) {
    error_log("Registration details report error: " . $e->getMessage());
}

$csrf_token = generate_csrf_token();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Details Report - Subject Allotment System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .card { border: none; border-radius: 15px; box-shadow: 0 0 20px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .pool-stats { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 15px; }
        .preference-badge { margin: 2px; font-size: 0.8rem; }
        .status-frozen { background-color: #dc3545; color: white; }
        .status-saved { background-color: #ffc107; color: dark; }
        .subject-demand { background: #f8f9fa; padding: 10px; border-radius: 8px; margin: 5px 0; }
        @media print {
            .no-print { display: none !important; }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary no-print">
        <div class="container-fluid">
            <a class="navbar-brand" href="admin_dashboard.php">
                <i class="fas fa-graduation-cap me-2"></i>Subject Allotment System
            </a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="reports.php">
                    <i class="fas fa-arrow-left me-2"></i>Back to Reports
                </a>
                <a class="nav-link" href="admin_dashboard.php">
                    <i class="fas fa-home me-2"></i>Dashboard
                </a>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2><i class="fas fa-clipboard-list me-2"></i>Student Registration Details Report</h2>
            <div class="btn-group no-print">
                <button type="button" class="btn btn-success" onclick="exportCSV()">
                    <i class="fas fa-file-csv me-2"></i>Export Full CSV
                </button>
                <button type="button" class="btn btn-primary" onclick="window.print()">
                    <i class="fas fa-print me-2"></i>Print
                </button>
            </div>
        </div>

        <!-- Filters -->
        <div class="card mb-4 no-print">
            <div class="card-body">
                <form method="GET" action="" class="row g-3">
                    <div class="col-md-3">
                        <label for="pool" class="form-label">Subject Pool</label>
                        <select class="form-select" id="pool" name="pool">
                            <option value="">All Pools</option>
                            <?php foreach ($pools as $pool): ?>
                                <option value="<?php echo $pool['id']; ?>" <?php echo $pool_filter == $pool['id'] ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($pool['pool_name'] . ' - ' . $pool['semester']); ?>
                                    (<?php echo $pool['registrations']; ?> registrations)
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label for="programme" class="form-label">Programme</label>
                        <select class="form-select" id="programme" name="programme">
                            <option value="">All Programmes</option>
                            <?php foreach ($programmes as $prog): ?>
                                <option value="<?php echo $prog; ?>" <?php echo $programme_filter == $prog ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($prog); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-2">
                        <label for="batch" class="form-label">Batch</label>
                        <select class="form-select" id="batch" name="batch">
                            <option value="">All Batches</option>
                            <?php foreach ($batches as $batch): ?>
                                <option value="<?php echo $batch; ?>" <?php echo $batch_filter == $batch ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($batch); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-2">
                        <label for="status" class="form-label">Status</label>
                        <select class="form-select" id="status" name="status">
                            <option value="">All Status</option>
                            <option value="frozen" <?php echo $status_filter == 'frozen' ? 'selected' : ''; ?>>Frozen</option>
                            <option value="saved" <?php echo $status_filter == 'saved' ? 'selected' : ''; ?>>Saved</option>
                        </select>
                    </div>
                    <div class="col-md-2">
                        <label class="form-label">&nbsp;</label>
                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-filter me-2"></i>Filter
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>

        <!-- Pool Statistics -->
        <?php if (!empty($pool_statistics)): ?>
        <div class="card mb-4">
            <div class="card-header bg-info text-white">
                <h5 class="mb-0"><i class="fas fa-chart-bar me-2"></i>Pool-wise Statistics & Subject Demand</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <?php foreach ($pool_statistics as $pool_id => $stats): ?>
                    <div class="col-md-6 mb-3">
                        <div class="pool-stats">
                            <h5><?php echo htmlspecialchars($stats['pool_name']); ?></h5>
                            <div class="row text-center">
                                <div class="col-4">
                                    <div class="h3"><?php echo $stats['total']; ?></div>
                                    <small>Total Registered</small>
                                </div>
                                <div class="col-4">
                                    <div class="h3"><?php echo $stats['frozen']; ?></div>
                                    <small>Frozen</small>
                                </div>
                                <div class="col-4">
                                    <div class="h3"><?php echo $stats['allotted']; ?></div>
                                    <small>Allotted</small>
                                </div>
                            </div>
                            
                            <?php if (!empty($stats['subjects'])): ?>
                            <hr>
                            <h6>Subject Demand:</h6>
                            <?php 
                            arsort($stats['subjects']);
                            foreach ($stats['subjects'] as $subject_code => $count): 
                                // Get subject name
                                $subj_stmt = $conn->prepare("SELECT subject_name, intake FROM subject_pools WHERE subject_code = ? LIMIT 1");
                                $subj_stmt->execute([$subject_code]);
                                $subject_info = $subj_stmt->fetch();
                            ?>
                            <div class="subject-demand">
                                <strong><?php echo htmlspecialchars($subject_code); ?></strong>
                                <?php if ($subject_info): ?>
                                    - <?php echo htmlspecialchars($subject_info['subject_name']); ?>
                                    <span class="float-end">
                                        <span class="badge bg-light text-dark"><?php echo $count; ?> students</span>
                                        <span class="badge bg-warning text-dark">Intake: <?php echo $subject_info['intake']; ?></span>
                                    </span>
                                <?php else: ?>
                                    <span class="float-end">
                                        <span class="badge bg-light text-dark"><?php echo $count; ?> students</span>
                                    </span>
                                <?php endif; ?>
                            </div>
                            <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <!-- Detailed Registration Table -->
        <div class="card">
            <div class="card-header bg-success text-white">
                <h5 class="mb-0">
                    <i class="fas fa-users me-2"></i>Detailed Registration Information
                    <span class="badge bg-light text-dark float-end"><?php echo count($registration_data); ?> records</span>
                </h5>
            </div>
            <div class="card-body">
                <?php if (empty($registration_data)): ?>
                    <div class="text-center py-5">
                        <i class="fas fa-info-circle fa-4x text-muted mb-3"></i>
                        <h5>No registration data found</h5>
                        <p>Try adjusting the filters or check if students have registered.</p>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover" id="registrationTable">
                            <thead class="table-light">
                                <tr>
                                    <th>Reg No</th>
                                    <th>Name</th>
                                    <th>Programme</th>
                                    <th>Batch</th>
                                    <th>Pool</th>
                                    <th>All Preferences</th>
                                    <th>Status</th>
                                    <th>Academic</th>
                                    <th>Allotted</th>
                                    <th>Contact</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($registration_data as $data): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($data['regno']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($data['name']); ?></td>
                                    <td><?php echo htmlspecialchars($data['programme']); ?></td>
                                    <td><?php echo htmlspecialchars($data['batch']); ?></td>
                                    <td>
                                        <span class="badge bg-primary"><?php echo htmlspecialchars($data['pool_name']); ?></span>
                                    </td>
                                    <td>
                                        <?php 
                                        if ($data['priority_order']) {
                                            $priorities = json_decode($data['priority_order'], true);
                                            if ($priorities) {
                                                usort($priorities, function($a, $b) { return $a['priority'] - $b['priority']; });
                                                
                                                echo '<div class="d-flex flex-wrap">';
                                                foreach ($priorities as $pref) {
                                                    // Get subject name
                                                    $subj_stmt = $conn->prepare("SELECT subject_name FROM subject_pools WHERE subject_code = ? LIMIT 1");
                                                    $subj_stmt->execute([$pref['subject_code']]);
                                                    $subject = $subj_stmt->fetch();
                                                    
                                                    $badge_color = $pref['priority'] == 1 ? 'success' : ($pref['priority'] <= 3 ? 'warning' : 'secondary');
                                                    echo '<span class="badge bg-' . $badge_color . ' preference-badge" title="' . ($subject ? htmlspecialchars($subject['subject_name']) : '') . '">';
                                                    echo $pref['priority'] . '. ' . htmlspecialchars($pref['subject_code']);
                                                    echo '</span>';
                                                }
                                                echo '</div>';
                                            }
                                        } else {
                                            echo '<span class="text-muted">No preferences set</span>';
                                        }
                                        ?>
                                    </td>
                                    <td>
                                        <span class="badge <?php echo $data['status'] == 'frozen' ? 'status-frozen' : 'status-saved'; ?>">
                                            <?php echo ucfirst($data['status']); ?>
                                        </span>
                                        <?php if ($data['frozen_at']): ?>
                                            <br><small><?php echo date('M j, h:i A', strtotime($data['frozen_at'])); ?></small>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($data['cgpa'] !== null): ?>
                                            CGPA: <span class="badge bg-info"><?php echo number_format($data['cgpa'], 2); ?></span><br>
                                        <?php endif; ?>
                                        Backlogs: <span class="badge <?php echo $data['backlogs'] > 0 ? 'bg-danger' : 'bg-success'; ?>">
                                            <?php echo $data['backlogs'] ?? 0; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?php if ($data['allotted_subject']): ?>
                                            <?php
                                            // Get allotted subject name
                                            $subj_stmt = $conn->prepare("SELECT subject_name FROM subject_pools WHERE subject_code = ? LIMIT 1");
                                            $subj_stmt->execute([$data['allotted_subject']]);
                                            $allotted = $subj_stmt->fetch();
                                            ?>
                                            <span class="badge bg-success" title="<?php echo $allotted ? htmlspecialchars($allotted['subject_name']) : ''; ?>">
                                                <?php echo htmlspecialchars($data['allotted_subject']); ?>
                                            </span>
                                        <?php else: ?>
                                            <span class="badge bg-secondary">Not Allotted</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <small>
                                            <i class="fas fa-envelope"></i> <?php echo htmlspecialchars($data['email']); ?><br>
                                            <i class="fas fa-phone"></i> <?php echo htmlspecialchars($data['mobile']); ?>
                                        </small>
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

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
    <script>
        $(document).ready(function() {
            $('#registrationTable').DataTable({
                responsive: true,
                pageLength: 25,
                order: [[4, 'asc'], [6, 'desc']], // Sort by pool, then status
                columnDefs: [
                    { targets: [5, 9], orderable: false } // Disable sorting for preferences and contact
                ]
            });
        });

        function exportCSV() {
            const params = new URLSearchParams(window.location.search);
            params.set('export', 'csv');
            window.location.href = 'registration_details_report.php?' + params.toString();
        }
    </script>
</body>
</html>