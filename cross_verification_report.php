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
$semester_filter = $_GET['semester'] ?? '';
$section_filter = $_GET['section'] ?? '';

// Handle CSV export
if (isset($_GET['export']) && $_GET['export'] == 'csv') {
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="cross_verification_report_' . date('Y-m-d') . '.csv"');
    
    $output = fopen('php://output', 'w');
    
    // CSV headers
    fputcsv($output, ['Registration No', 'Student Name', 'Programme', 'Batch', 'Semester', 'Section', 'Email', 'Mobile', 'Registered Status', 'Pool Name', 'Registration Date', 'Frozen Status', 'Allotment Status']);
    
    // Get active pools for eligibility check
    $pool_stmt = $conn->query("
        SELECT DISTINCT batch, semester, allowed_programmes 
        FROM subject_pools 
        WHERE is_active = 1
    ");
    $active_pools = $pool_stmt->fetchAll();
    
    // Build eligibility conditions
    $eligibility_conditions = [];
    foreach ($active_pools as $pool) {
        $programmes = json_decode($pool['allowed_programmes'], true);
        if (!empty($programmes)) {
            foreach ($programmes as $prog) {
                $eligibility_conditions[] = "(u.batch = " . $conn->quote($pool['batch']) . 
                                          " AND u.semester = " . $conn->quote($pool['semester']) . 
                                          " AND u.programme = " . $conn->quote($prog) . ")";
            }
        }
    }
    
    // Build WHERE clause for CSV
    $where_conditions = [];
    $params = [];
    
    if (!empty($eligibility_conditions)) {
        $where_conditions[] = "(" . implode(" OR ", $eligibility_conditions) . ")";
    } else {
        $where_conditions[] = "1=0";
    }
    
    if ($batch_filter) {
        $where_conditions[] = 'u.batch = ?';
        $params[] = $batch_filter;
    }
    if ($programme_filter) {
        $where_conditions[] = 'u.programme = ?';
        $params[] = $programme_filter;
    }
    if ($semester_filter) {
        $where_conditions[] = 'u.semester = ?';
        $params[] = $semester_filter;
    }
    if ($section_filter) {
        $where_conditions[] = 'u.classSection = ?';
        $params[] = $section_filter;
    }
    
    $where_clause = implode(' AND ', $where_conditions);
    
    if ($attendance_conn) {
        $stmt = $attendance_conn->prepare("
            SELECT 
                u.regid,
                u.name,
                u.programme,
                u.batch,
                u.semester,
                u.classSection,
                u.email,
                u.mobile
            FROM user u
            WHERE $where_clause
            ORDER BY u.programme, u.batch, u.classSection, u.regid
        ");
        
        $stmt->execute($params);
        
        while ($student = $stmt->fetch()) {
            // Check registration status
            $reg_stmt = $conn->prepare("
                SELECT sr.*, sp.pool_name 
                FROM student_registrations sr
                JOIN subject_pools sp ON sr.pool_id = sp.id
                WHERE sr.regno = ?
            ");
            $reg_stmt->execute([$student['regid']]);
            $registration = $reg_stmt->fetch();
            
            // Check allotment status
            $allot_stmt = $conn->prepare("
                SELECT COUNT(*) as allotted 
                FROM subject_allotments 
                WHERE regno = ?
            ");
            $allot_stmt->execute([$student['regid']]);
            $allotment = $allot_stmt->fetch();
            
            fputcsv($output, [
                $student['regid'],
                $student['name'],
                $student['programme'],
                $student['batch'],
                $student['semester'],
                $student['classSection'],
                $student['email'],
                $student['mobile'],
                $registration ? 'Registered' : 'Not Registered',
                $registration ? $registration['pool_name'] : '-',
                $registration ? $registration['registered_at'] : '-',
                $registration ? ucfirst($registration['status']) : '-',
                $allotment['allotted'] > 0 ? 'Allotted' : 'Not Allotted'
            ]);
        }
    }
    
    fclose($output);
    exit();
}

// Get data for report
$cross_verification_data = [];
$total_students = 0;
$registered_students = 0;
$frozen_students = 0;
$allotted_students = 0;

try {
    if ($attendance_conn) {
        // First, get all active subject pools to determine which students are eligible
        $pool_stmt = $conn->query("
            SELECT DISTINCT batch, semester, allowed_programmes 
            FROM subject_pools 
            WHERE is_active = 1
        ");
        $active_pools = $pool_stmt->fetchAll();
        
        // Build conditions for eligible students based on active pools
        $eligibility_conditions = [];
        foreach ($active_pools as $pool) {
            $programmes = json_decode($pool['allowed_programmes'], true);
            if (!empty($programmes)) {
                foreach ($programmes as $prog) {
                    $eligibility_conditions[] = "(u.batch = " . $conn->quote($pool['batch']) . 
                                              " AND u.semester = " . $conn->quote($pool['semester']) . 
                                              " AND u.programme = " . $conn->quote($prog) . ")";
                }
            }
        }
        
        // Build WHERE clause
        $where_conditions = [];
        $params = [];
        
        // Only show students eligible for at least one active pool
        if (!empty($eligibility_conditions)) {
            $where_conditions[] = "(" . implode(" OR ", $eligibility_conditions) . ")";
        } else {
            // No active pools, show no students
            $where_conditions[] = "1=0";
        }
        
        if ($batch_filter) {
            $where_conditions[] = 'u.batch = ?';
            $params[] = $batch_filter;
        }
        if ($programme_filter) {
            $where_conditions[] = 'u.programme = ?';
            $params[] = $programme_filter;
        }
        if ($semester_filter) {
            $where_conditions[] = 'u.semester = ?';
            $params[] = $semester_filter;
        }
        if ($section_filter) {
            $where_conditions[] = 'u.classSection = ?';
            $params[] = $section_filter;
        }
        
        $where_clause = implode(' AND ', $where_conditions);
        
        // Get total eligible student count
        $stmt = $attendance_conn->prepare("SELECT COUNT(*) as total FROM user u WHERE $where_clause");
        $stmt->execute($params);
        $total_students = $stmt->fetch()['total'];
        
        // Get students with pagination for display
        $page = intval($_GET['page'] ?? 1);
        $per_page = 50;
        $offset = ($page - 1) * $per_page;
        
        $stmt = $attendance_conn->prepare("
            SELECT 
                u.regid,
                u.name,
                u.programme,
                u.batch,
                u.semester,
                u.classSection,
                u.email,
                u.mobile
            FROM user u
            WHERE $where_clause
            ORDER BY u.programme, u.batch, u.classSection, u.regid
            LIMIT $per_page OFFSET $offset
        ");
        
        $stmt->execute($params);
        $students = $stmt->fetchAll();
        
        // Get registration and allotment status for each student
        foreach ($students as $student) {
            // Check registration
            $reg_stmt = $conn->prepare("
                SELECT sr.*, sp.pool_name, sp.semester as pool_semester, sp.batch as pool_batch
                FROM student_registrations sr
                JOIN subject_pools sp ON sr.pool_id = sp.id
                WHERE sr.regno = ?
            ");
            $reg_stmt->execute([$student['regid']]);
            $registration = $reg_stmt->fetch();
            
            // Check allotment
            $allot_stmt = $conn->prepare("
                SELECT sa.*, sp.subject_name, sp.subject_code
                FROM subject_allotments sa
                JOIN subject_pools sp ON sa.subject_code = sp.subject_code
                WHERE sa.regno = ?
            ");
            $allot_stmt->execute([$student['regid']]);
            $allotment = $allot_stmt->fetch();
            
            $student['registration'] = $registration;
            $student['allotment'] = $allotment;
            
            $cross_verification_data[] = $student;
            
            if ($registration) {
                $registered_students++;
                if ($registration['status'] == 'frozen') {
                    $frozen_students++;
                }
            }
            if ($allotment) {
                $allotted_students++;
            }
        }
        
        // Calculate total pages
        $total_pages = ceil($total_students / $per_page);
        
        // Get overall statistics for eligible students only
        // First, get list of all eligible regnos
        $eligible_query = "SELECT u.regid FROM user u WHERE " . 
                         (!empty($eligibility_conditions) ? "(" . implode(" OR ", $eligibility_conditions) . ")" : "1=0");
        $eligible_stmt = $attendance_conn->query($eligible_query);
        $eligible_regnos = $eligible_stmt->fetchAll(PDO::FETCH_COLUMN);
        
        if (!empty($eligible_regnos)) {
            $placeholders = str_repeat('?,', count($eligible_regnos) - 1) . '?';
            
            $stmt = $conn->prepare("SELECT COUNT(DISTINCT regno) as registered FROM student_registrations WHERE regno IN ($placeholders)");
            $stmt->execute($eligible_regnos);
            $total_registered = $stmt->fetch()['registered'];
            
            $stmt = $conn->prepare("SELECT COUNT(DISTINCT regno) as frozen FROM student_registrations WHERE status = 'frozen' AND regno IN ($placeholders)");
            $stmt->execute($eligible_regnos);
            $total_frozen = $stmt->fetch()['frozen'];
            
            $stmt = $conn->prepare("SELECT COUNT(DISTINCT regno) as allotted FROM subject_allotments WHERE regno IN ($placeholders)");
            $stmt->execute($eligible_regnos);
            $total_allotted = $stmt->fetch()['allotted'];
        } else {
            $total_registered = $total_frozen = $total_allotted = 0;
        }
        
        // Update total students to reflect eligible count
        $total_students = count($eligible_regnos);
        
        // Get filter options - only from eligible students
        $stmt = $attendance_conn->prepare("SELECT DISTINCT batch FROM user u WHERE $where_clause ORDER BY batch DESC");
        $stmt->execute($params);
        $batches = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        $stmt = $attendance_conn->prepare("SELECT DISTINCT programme FROM user u WHERE $where_clause ORDER BY programme");
        $stmt->execute($params);
        $programmes = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        $stmt = $attendance_conn->prepare("SELECT DISTINCT semester FROM user u WHERE $where_clause ORDER BY semester");
        $stmt->execute($params);
        $semesters = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        $stmt = $attendance_conn->prepare("SELECT DISTINCT classSection FROM user u WHERE $where_clause ORDER BY classSection");
        $stmt->execute($params);
        $sections = $stmt->fetchAll(PDO::FETCH_COLUMN);
    }
    
} catch(Exception $e) {
    error_log("Cross verification error: " . $e->getMessage());
}

// Calculate percentages
$registration_percentage = $total_students > 0 ? round(($total_registered / $total_students) * 100, 1) : 0;
$frozen_percentage = $total_registered > 0 ? round(($total_frozen / $total_registered) * 100, 1) : 0;
$allotment_percentage = $total_frozen > 0 ? round(($total_allotted / $total_frozen) * 100, 1) : 0;

$csrf_token = generate_csrf_token();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cross Verification Report - Subject Allotment System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .card { border: none; border-radius: 15px; box-shadow: 0 0 20px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .stat-card { text-align: center; padding: 20px; }
        .stat-number { font-size: 3rem; font-weight: bold; }
        .progress-custom { height: 30px; border-radius: 15px; }
        .progress-bar { border-radius: 15px; }
        .status-registered { background-color: #d4edda; }
        .status-not-registered { background-color: #f8d7da; }
        .filter-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
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
            <h2><i class="fas fa-check-double me-2"></i>Cross Verification Report</h2>
            <div class="btn-group no-print">
                <button type="button" class="btn btn-success" onclick="exportCSV()">
                    <i class="fas fa-file-csv me-2"></i>Export Full CSV
                </button>
                <button type="button" class="btn btn-primary" onclick="window.print()">
                    <i class="fas fa-print me-2"></i>Print
                </button>
            </div>
        </div>

        <!-- Overall Statistics -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stat-card bg-primary text-white">
                    <div class="stat-number"><?php echo number_format($total_students); ?></div>
                    <div>Eligible Students</div>
                    <small>Based on active subject pools</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card bg-success text-white">
                    <div class="stat-number"><?php echo number_format($total_registered); ?></div>
                    <div>Registered Students</div>
                    <div class="mt-2">
                        <div class="progress progress-custom">
                            <div class="progress-bar bg-light" style="width: <?php echo $registration_percentage; ?>%">
                                <?php echo $registration_percentage; ?>%
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card bg-warning text-dark">
                    <div class="stat-number"><?php echo number_format($total_frozen); ?></div>
                    <div>Frozen Preferences</div>
                    <div class="mt-2">
                        <div class="progress progress-custom">
                            <div class="progress-bar bg-dark" style="width: <?php echo $frozen_percentage; ?>%">
                                <?php echo $frozen_percentage; ?>%
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card bg-info text-white">
                    <div class="stat-number"><?php echo number_format($total_allotted); ?></div>
                    <div>Allotted Students</div>
                    <div class="mt-2">
                        <div class="progress progress-custom">
                            <div class="progress-bar bg-light" style="width: <?php echo $allotment_percentage; ?>%">
                                <?php echo $allotment_percentage; ?>%
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Filters -->
        <div class="card filter-card mb-4 no-print">
            <div class="card-body">
                <form method="GET" action="" class="row g-3">
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
                        <label for="semester" class="form-label">Semester</label>
                        <select class="form-select" id="semester" name="semester">
                            <option value="">All Semesters</option>
                            <?php foreach ($semesters as $sem): ?>
                                <option value="<?php echo $sem; ?>" <?php echo $semester_filter == $sem ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($sem); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-2">
                        <label for="section" class="form-label">Section</label>
                        <select class="form-select" id="section" name="section">
                            <option value="">All Sections</option>
                            <?php foreach ($sections as $section): ?>
                                <option value="<?php echo $section; ?>" <?php echo $section_filter == $section ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($section); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">&nbsp;</label>
                        <div class="d-grid">
                            <button type="submit" class="btn btn-light">
                                <i class="fas fa-filter me-2"></i>Apply Filters
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>

        <!-- Verification Table -->
        <div class="card">
            <div class="card-header bg-info text-white">
                <h5 class="mb-0">
                    <i class="fas fa-users me-2"></i>Eligible Students Cross Verification
                    <small class="float-end">Page <?php echo $page; ?> of <?php echo $total_pages; ?></small>
                </h5>
                <small>Showing only students eligible for active subject pools</small>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-bordered table-hover">
                        <thead class="table-light">
                            <tr>
                                <th>Reg No</th>
                                <th>Name</th>
                                <th>Programme</th>
                                <th>Batch</th>
                                <th>Semester</th>
                                <th>Section</th>
                                <th>Registration Status</th>
                                <th>Pool</th>
                                <th>Frozen</th>
                                <th>Allotted</th>
                                <th>Contact</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($cross_verification_data as $data): ?>
                            <tr class="<?php echo $data['registration'] ? 'status-registered' : 'status-not-registered'; ?>">
                                <td><strong><?php echo htmlspecialchars($data['regid']); ?></strong></td>
                                <td><?php echo htmlspecialchars($data['name']); ?></td>
                                <td><?php echo htmlspecialchars($data['programme']); ?></td>
                                <td><?php echo htmlspecialchars($data['batch']); ?></td>
                                <td><?php echo htmlspecialchars($data['semester']); ?></td>
                                <td><?php echo htmlspecialchars($data['classSection']); ?></td>
                                <td>
                                    <?php if ($data['registration']): ?>
                                        <span class="badge bg-success">Registered</span>
                                    <?php else: ?>
                                        <span class="badge bg-danger">Not Registered</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php echo $data['registration'] ? htmlspecialchars($data['registration']['pool_name']) : '-'; ?>
                                </td>
                                <td>
                                    <?php if ($data['registration']): ?>
                                        <?php if ($data['registration']['status'] == 'frozen'): ?>
                                            <span class="badge bg-primary">Yes</span>
                                        <?php else: ?>
                                            <span class="badge bg-warning">No</span>
                                        <?php endif; ?>
                                    <?php else: ?>
                                        -
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($data['allotment']): ?>
                                        <span class="badge bg-info"><?php echo htmlspecialchars($data['allotment']['subject_code']); ?></span>
                                    <?php else: ?>
                                        <span class="badge bg-secondary">No</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <small>
                                        <?php echo htmlspecialchars($data['email']); ?><br>
                                        <?php echo htmlspecialchars($data['mobile']); ?>
                                    </small>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Pagination -->
                <?php if ($total_pages > 1): ?>
                <nav class="mt-3">
                    <ul class="pagination justify-content-center">
                        <?php for ($i = 1; $i <= min($total_pages, 10); $i++): ?>
                        <li class="page-item <?php echo $i == $page ? 'active' : ''; ?>">
                            <a class="page-link" href="?page=<?php echo $i; ?>&<?php echo http_build_query($_GET); ?>">
                                <?php echo $i; ?>
                            </a>
                        </li>
                        <?php endfor; ?>
                    </ul>
                </nav>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function exportCSV() {
            const params = new URLSearchParams(window.location.search);
            params.set('export', 'csv');
            window.location.href = 'cross_verification_report.php?' + params.toString();
        }
    </script>
</body>
</html>