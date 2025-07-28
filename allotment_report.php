<?php
require_once 'dbconfig.php';

// Check admin authentication
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header("Location: admin_login.php");
    exit();
}

// Handle CSV export
if (isset($_GET['export']) && $_GET['export'] == 'csv') {
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="allotment_report_' . date('Y-m-d') . '.csv"');
    
    $output = fopen('php://output', 'w');
    
    // CSV headers
    fputcsv($output, ['Registration No', 'Student Name', 'Programme', 'Batch', 'Semester', 'Email', 'Mobile', 'Allotted Subject', 'Subject Code', 'Pool Name', 'Pool ID', 'Allotment Rank', 'Allotment Date', 'Allotment Reason']);
    
    // Get ALL allotments
    $query = "
        SELECT 
            sa.regno,
            sa.subject_code,
            sa.allotment_rank,
            sa.allotted_at,
            sa.allotment_reason,
            sa.pool_id,
            sp.subject_name,
            sp.pool_name,
            sp.batch as pool_batch,
            sp.semester as pool_semester
        FROM subject_allotments sa
        LEFT JOIN subject_pools sp ON sa.subject_code = sp.subject_code AND sa.pool_id = sp.id
        ORDER BY sa.id DESC
    ";
    
    $stmt = $conn->prepare($query);
    $stmt->execute();
    $allotments = $stmt->fetchAll();
    
    foreach ($allotments as $allotment) {
        $student_data = [
            'regno' => $allotment['regno'],
            'student_name' => 'N/A',
            'programme' => 'N/A',
            'batch' => 'N/A',
            'semester' => 'N/A',
            'email' => 'N/A',
            'mobile' => 'N/A'
        ];
        
        // Try to get student details from attendance database
        if ($attendance_conn) {
            try {
                $student_stmt = $attendance_conn->prepare("
                    SELECT 
                        u.regid as regno,
                        u.name as student_name,
                        u.programme,
                        u.batch,
                        u.semester,
                        u.email,
                        u.mobile
                    FROM user u
                    WHERE u.regid = ?
                ");
                $student_stmt->execute([$allotment['regno']]);
                $student = $student_stmt->fetch();
                
                if ($student) {
                    $student_data = $student;
                }
            } catch (Exception $e) {
                // Continue with default N/A values
            }
        }
        
        fputcsv($output, [
            $student_data['regno'],
            $student_data['student_name'],
            $student_data['programme'],
            $student_data['batch'],
            $student_data['semester'],
            $student_data['email'],
            $student_data['mobile'],
            $allotment['subject_name'] ?: 'N/A',
            $allotment['subject_code'],
            $allotment['pool_name'] ?: 'N/A',
            $allotment['pool_id'],
            $allotment['allotment_rank'],
            $allotment['allotted_at'],
            $allotment['allotment_reason']
        ]);
    }
    
    fclose($output);
    exit();
}

// Get ALL allotment data
$allotment_data = [];
$total_allotted = 0;

try {
    // Count total records first
    $count_stmt = $conn->query("SELECT COUNT(*) as total FROM subject_allotments");
    $total_in_db = $count_stmt->fetch()['total'];
    
    // Get ALL allotments without any filtering
    $query = "
        SELECT 
            sa.id,
            sa.regno,
            sa.subject_code,
            sa.allotment_rank,
            sa.allotted_at,
            sa.allotment_reason,
            sa.pool_id,
            sp.subject_name,
            sp.pool_name,
            sp.semester as pool_semester,
            sp.batch as pool_batch
        FROM subject_allotments sa
        LEFT JOIN subject_pools sp ON sa.subject_code = sp.subject_code AND sa.pool_id = sp.id
        ORDER BY sa.id DESC
    ";
    
    $stmt = $conn->prepare($query);
    $stmt->execute();
    $allotments = $stmt->fetchAll();
    
    foreach ($allotments as $allotment) {
        $student_data = [
            'regno' => $allotment['regno'],
            'student_name' => 'Not Found',
            'programme' => 'N/A',
            'batch' => 'N/A',
            'semester' => 'N/A',
            'email' => 'N/A',
            'mobile' => 'N/A'
        ];
        
        // Try to get student details
        if ($attendance_conn) {
            try {
                $student_stmt = $attendance_conn->prepare("
                    SELECT 
                        u.regid as regno,
                        u.name as student_name,
                        u.programme,
                        u.batch,
                        u.semester,
                        u.email,
                        u.mobile
                    FROM user u
                    WHERE u.regid = ?
                ");
                $student_stmt->execute([$allotment['regno']]);
                $student = $student_stmt->fetch();
                
                if ($student) {
                    $student_data = $student;
                }
            } catch (Exception $e) {
                // Continue with default values
            }
        }
        
        // Merge all data
        $merged_data = array_merge($student_data, $allotment);
        $allotment_data[] = $merged_data;
        $total_allotted++;
    }
    
} catch(Exception $e) {
    error_log("Allotment report error: " . $e->getMessage());
}

$csrf_token = generate_csrf_token();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Student Allotment Report - Subject Allotment System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/buttons/2.4.2/css/buttons.bootstrap5.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .card { border: none; border-radius: 15px; box-shadow: 0 0 20px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .table th { background-color: #f8f9fa; }
        @media print {
            .no-print { display: none !important; }
            .card { box-shadow: none !important; }
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
            <div>
                <h2><i class="fas fa-trophy me-2"></i>Student Allotment Report</h2>
                <small class="text-muted">Total Records: <?php echo $total_allotted; ?></small>
            </div>
            <div class="btn-group no-print">
                <button type="button" class="btn btn-success" onclick="exportCSV()">
                    <i class="fas fa-file-csv me-2"></i>Export CSV
                </button>
                <button type="button" class="btn btn-primary" onclick="window.print()">
                    <i class="fas fa-print me-2"></i>Print
                </button>
            </div>
        </div>

        <!-- Main Report Table -->
        <div class="card">
            <div class="card-body">
                <?php if (empty($allotment_data)): ?>
                    <div class="text-center py-5">
                        <i class="fas fa-info-circle fa-4x text-muted mb-3"></i>
                        <h5>No allotment data found</h5>
                        <p>Please run the allotment process first.</p>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover" id="allotmentTable">
                            <thead class="table-light">
                                <tr>
                                    <th>Reg No</th>
                                    <th>Student Name</th>
                                    <th>Programme</th>
                                    <th>Batch</th>
                                    <th>Semester</th>
                                    <th>Allotted Subject</th>
                                    <th>Subject Code</th>
                                    <th>Pool Name</th>
                                    <th>Rank</th>
                                    <th>Contact</th>
                                    <th>Allotted On</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($allotment_data as $data): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($data['regno']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($data['student_name']); ?></td>
                                    <td><?php echo htmlspecialchars($data['programme']); ?></td>
                                    <td><?php echo htmlspecialchars($data['batch']); ?></td>
                                    <td><?php echo htmlspecialchars($data['semester']); ?></td>
                                    <td><span class="badge bg-success"><?php echo htmlspecialchars($data['subject_name'] ?: 'N/A'); ?></span></td>
                                    <td><span class="badge bg-info"><?php echo htmlspecialchars($data['subject_code']); ?></span></td>
                                    <td><?php echo htmlspecialchars($data['pool_name'] ?: 'Pool ' . $data['pool_id']); ?></td>
                                    <td><span class="badge bg-primary"><?php echo $data['allotment_rank']; ?></span></td>
                                    <td>
                                        <small>
                                            <?php echo htmlspecialchars($data['email']); ?><br>
                                            <?php echo htmlspecialchars($data['mobile']); ?>
                                        </small>
                                    </td>
                                    <td>
                                        <small><?php echo date('d-M-Y H:i', strtotime($data['allotted_at'])); ?></small>
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
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.bootstrap5.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
    <script>
        $(document).ready(function() {
            $('#allotmentTable').DataTable({
                responsive: true,
                paging: false,
                lengthMenu: [ [10, 25, 50, -1], [10, 25, 50, "All"] ],
                pageLength: -1,
                order: [[0, 'asc']],
                dom: 'Bfrtip',
                buttons: [
                    {
                        extend: 'excel',
                        text: '<i class="fas fa-file-excel me-1"></i>Excel',
                        className: 'btn btn-success btn-sm',
                        title: 'Student Allotment Report - ' + new Date().toLocaleDateString(),
                        exportOptions: {
                            modifier: {
                                page: 'all'
                            }
                        }
                    }
                ],
                language: {
                    search: "Search in table:"
                },
                deferRender: false,
                scrollY: false,
                scrollCollapse: false
            });
        });

        function exportCSV() {
            window.location.href = 'allotment_report.php?export=csv';
        }
    </script>
</body>
</html>