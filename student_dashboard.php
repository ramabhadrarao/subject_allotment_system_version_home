<?php
require_once 'dbconfig.php';

// Check student authentication
if (!isset($_SESSION['student_logged_in']) || $_SESSION['student_logged_in'] !== true) {
    header("Location: student_login.php");
    exit();
}

// Validate session
if (!validate_session($conn, 'student', $_SESSION['student_regno'])) {
    session_destroy();
    header("Location: student_login.php");
    exit();
}

$regno = $_SESSION['student_regno'];
$pool_id = $_SESSION['student_pool_id'];
$error_message = '';
$success_message = '';

// First, get student registration details and available subjects
try {
    $stmt = $conn->prepare("SELECT sr.*, sp.pool_name, sp.semester, sp.batch FROM student_registrations sr JOIN subject_pools sp ON sr.pool_id = sp.id WHERE sr.regno = ? AND sr.pool_id = ?");
    $stmt->execute([$regno, $pool_id]);
    $student_registration = $stmt->fetch();
    
    if (!$student_registration) {
        header("Location: student_login.php");
        exit();
    }
    
    // Get student's programme from the existing database
    $student_programme = null;
    if ($attendance_conn) {
        $stmt = $attendance_conn->prepare("SELECT programme FROM user WHERE regid = ?");
        $stmt->execute([$regno]);
        $student_data = $stmt->fetch();
        if ($student_data) {
            $student_programme = $student_data['programme'];
        }
    }
    
    // Get available subjects for this pool that are allowed for the student's programme
    if ($student_programme) {
        $stmt = $conn->prepare("
            SELECT * FROM subject_pools 
            WHERE (id = ? OR (pool_name = ? AND semester = ? AND batch = ?)) 
            AND is_active = 1 
            AND JSON_CONTAINS(allowed_programmes, JSON_QUOTE(?))
            ORDER BY subject_name
        ");
        $stmt->execute([
            $pool_id, 
            $student_registration['pool_name'], 
            $student_registration['semester'], 
            $student_registration['batch'],
            $student_programme
        ]);
    } else {
        // Fallback if programme not found - show all subjects in pool
        $stmt = $conn->prepare("
            SELECT * FROM subject_pools 
            WHERE (id = ? OR (pool_name = ? AND semester = ? AND batch = ?)) 
            AND is_active = 1 
            ORDER BY subject_name
        ");
        $stmt->execute([
            $pool_id, 
            $student_registration['pool_name'], 
            $student_registration['semester'], 
            $student_registration['batch']
        ]);
    }
    
    $available_subjects = $stmt->fetchAll();
    
    // Get current priorities
    $current_priorities = [];
    if (!empty($student_registration['priority_order'])) {
        $priority_data = json_decode($student_registration['priority_order'], true);
        if ($priority_data) {
            foreach ($priority_data as $item) {
                $current_priorities[$item['subject_code']] = $item['priority'];
            }
        }
    }
    
    // Get allotment result if exists
    $stmt = $conn->prepare("SELECT sa.*, sp.subject_name FROM subject_allotments sa JOIN subject_pools sp ON sa.subject_code = sp.subject_code WHERE sa.regno = ? AND sa.pool_id = ?");
    $stmt->execute([$regno, $pool_id]);
    $allotment_result = $stmt->fetch();
    
    // NEW: Check if results are published for this pool
    $results_published = false;
    $results_pending_publication = false;
    
    if ($allotment_result) {
        $stmt = $conn->prepare("SELECT results_published FROM result_publication WHERE pool_id = ? AND results_published = 1");
        $stmt->execute([$pool_id]);
        $publication_status = $stmt->fetch();
        $results_published = $publication_status ? true : false;
        
        // If results exist but not published, hide them from student
        if (!$results_published) {
            $allotment_result = null; // Hide the result
            $results_pending_publication = true; // Flag to show appropriate message
        }
    }
    
    // Get student academic data
    $stmt = $conn->prepare("SELECT * FROM student_academic_data WHERE regno = ?");
    $stmt->execute([$regno]);
    $academic_data = $stmt->fetch();

} catch(Exception $e) {
    error_log("Student dashboard data error: " . $e->getMessage());
    $available_subjects = [];
    $current_priorities = [];
    $allotment_result = null;
    $academic_data = null;
}

// Handle priority selection form (after we have $available_subjects)
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'save_priorities') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        log_security_event($conn, 'csrf_violation', 'high', 'CSRF token validation failed for priority selection', $regno);
        $error_message = 'Security validation failed. Please try again.';
    } else if (!prevent_resubmit($conn, 'student', $regno, 'priority_selection')) {
        $error_message = 'Form already submitted. Please refresh the page.';
    } else {
        try {
            // Check if already frozen
            $stmt = $conn->prepare("SELECT status FROM student_registrations WHERE regno = ? AND pool_id = ?");
            $stmt->execute([$regno, $pool_id]);
            $registration = $stmt->fetch();
            
            if ($registration && $registration['status'] == 'frozen') {
                $error_message = 'Your preferences are already frozen and cannot be modified.';
            } else {
                $priorities = [];
                $subject_priorities = $_POST['subject_priority'] ?? [];
                
                // Validate priorities - UPDATED VALIDATION
                $used_priorities = [];
                $has_valid_priority = false;
                $max_priority = count($available_subjects);
                
                foreach ($subject_priorities as $subject_code => $priority) {
                    $priority = intval($priority);
                    if ($priority > 0) {
                        // Check if priority exceeds the number of available subjects
                        if ($priority > $max_priority) {
                            $error_message = "Priority value cannot exceed $max_priority (the number of available subjects).";
                            break;
                        }
                        
                        if (in_array($priority, $used_priorities)) {
                            $error_message = "Duplicate priority $priority found. Each priority number must be unique.";
                            break;
                        }
                        $used_priorities[] = $priority;
                        $priorities[] = ['subject_code' => $subject_code, 'priority' => $priority];
                        $has_valid_priority = true;
                    }
                }
                
                if (empty($error_message)) {
                    if (!$has_valid_priority) {
                        $error_message = 'Please set at least one priority.';
                    }
                    // NEW VALIDATION: Check if all subjects have priorities
                    elseif (count($used_priorities) != $max_priority) {
                        $missing_count = $max_priority - count($used_priorities);
                        $error_message = "You must set priorities for ALL $max_priority subjects. You have $missing_count subject(s) without priorities.";
                    }
                    // Check for sequential numbers from 1 to max_priority
                    elseif (count($used_priorities) == $max_priority) {
                        sort($used_priorities);
                        for ($i = 0; $i < count($used_priorities); $i++) {
                            if ($used_priorities[$i] != ($i + 1)) {
                                $error_message = "You must use all priority numbers from 1 to $max_priority without gaps. Missing: " . ($i + 1);
                                break;
                            }
                        }
                    }
                    
                    if (empty($error_message)) {
                        // Sort by priority
                        usort($priorities, function($a, $b) {
                            return $a['priority'] - $b['priority'];
                        });
                        
                        // Update priorities
                        $stmt = $conn->prepare("UPDATE student_registrations SET priority_order = ?, last_updated_ip = ?, updated_at = NOW() WHERE regno = ? AND pool_id = ?");
                        $stmt->execute([json_encode($priorities), get_client_ip(), $regno, $pool_id]);
                        
                        log_activity($conn, 'student', $regno, 'priority_updated', 'student_registrations', null, null, $priorities);
                        $success_message = 'Priorities saved successfully!';
                        
                        // Refresh current priorities
                        $current_priorities = [];
                        foreach ($priorities as $item) {
                            $current_priorities[$item['subject_code']] = $item['priority'];
                        }
                    }
                }
            }
        } catch(Exception $e) {
            error_log("Priority save error: " . $e->getMessage());
            $error_message = 'An error occurred while saving priorities.';
        }
    }
}

// Handle freeze preferences
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'freeze_preferences') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        log_security_event($conn, 'csrf_violation', 'high', 'CSRF token validation failed for freeze preferences', $regno);
        $error_message = 'Security validation failed. Please try again.';
    } else if (!prevent_resubmit($conn, 'student', $regno, 'freeze_preferences')) {
        $error_message = 'Form already submitted. Please refresh the page.';
    } else {
        try {
            $stmt = $conn->prepare("SELECT priority_order FROM student_registrations WHERE regno = ? AND pool_id = ?");
            $stmt->execute([$regno, $pool_id]);
            $registration = $stmt->fetch();
            
            if (!$registration || empty($registration['priority_order']) || $registration['priority_order'] == '[]') {
                $error_message = 'Please set your priorities before freezing.';
            } else {
                // Check if all subjects have priorities before freezing
                $priority_data = json_decode($registration['priority_order'], true);
                if (count($priority_data) != count($available_subjects)) {
                    $error_message = 'You must set priorities for ALL subjects before freezing.';
                } else {
                    $stmt = $conn->prepare("UPDATE student_registrations SET status = 'frozen', frozen_at = NOW(), last_updated_ip = ? WHERE regno = ? AND pool_id = ?");
                    $stmt->execute([get_client_ip(), $regno, $pool_id]);
                    
                    log_activity($conn, 'student', $regno, 'preferences_frozen', 'student_registrations');
                    $success_message = 'Preferences frozen successfully! You can no longer modify your selections.';
                    
                    // Update status in current data
                    $student_registration['status'] = 'frozen';
                    $student_registration['frozen_at'] = date('Y-m-d H:i:s');
                }
            }
        } catch(Exception $e) {
            error_log("Freeze preferences error: " . $e->getMessage());
            $error_message = 'An error occurred while freezing preferences.';
        }
    }
}

$csrf_token = generate_csrf_token();
$form_token = generate_token();
log_activity($conn, 'student', $regno, 'dashboard_view');
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Student Dashboard - Subject Allotment System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .navbar-brand {
            font-weight: bold;
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .card:hover {
            transform: translateY(-2px);
            transition: all 0.3s ease;
        }
        .profile-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .priority-card {
            border-left: 5px solid #28a745;
        }
        .allotment-card {
            border-left: 5px solid #007bff;
        }
        .academic-card {
            border-left: 5px solid #ffc107;
        }
        .subject-item {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 10px;
            border: 2px solid transparent;
            transition: all 0.3s ease;
        }
        .subject-item:hover {
            border-color: #667eea;
            background: white;
        }
        .priority-input {
            max-width: 80px;
        }
        .priority-input.is-invalid {
            border-color: #dc3545;
        }
        .priority-input.is-valid {
            border-color: #28a745;
        }
        .status-frozen {
            background: linear-gradient(135deg, #dc3545 0%, #fd7e14 100%);
            color: white;
        }
        .status-saved {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
        }
        .allotment-success {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
        }
        .programme-info {
            background: #e3f2fd;
            border-radius: 8px;
            padding: 10px;
            margin-bottom: 15px;
        }
        .progress-container {
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #dee2e6;
        }
        @media (max-width: 768px) {
            .card {
                margin-bottom: 15px;
            }
            .subject-item {
                padding: 10px;
            }
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
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
                            <?php echo htmlspecialchars($regno); ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="refreshPage()">
                                <i class="fas fa-sync me-2"></i>Refresh
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="student_logout.php">
                                <i class="fas fa-sign-out-alt me-2"></i>Logout
                            </a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
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
            <!-- Left Column -->
            <div class="col-lg-4">
                <!-- Student Profile Card -->
                <div class="card profile-card">
                    <div class="card-body text-center">
                        <i class="fas fa-user-graduate fa-4x mb-3"></i>
                        <h4><?php echo htmlspecialchars($regno); ?></h4>
                        <p class="mb-2">
                            <i class="fas fa-envelope me-2"></i>
                            <?php echo htmlspecialchars($_SESSION['student_email']); ?>
                        </p>
                        <p class="mb-2">
                            <i class="fas fa-phone me-2"></i>
                            <?php echo htmlspecialchars($_SESSION['student_mobile']); ?>
                        </p>
                        <?php if ($student_programme): ?>
                        <p class="mb-2">
                            <i class="fas fa-graduation-cap me-2"></i>
                            <?php echo htmlspecialchars($student_programme); ?>
                        </p>
                        <?php endif; ?>
                        <hr class="bg-white">
                        <div class="row text-center">
                            <div class="col-6">
                                <strong>Pool</strong><br>
                                <?php echo htmlspecialchars($student_registration['pool_name']); ?>
                            </div>
                            <div class="col-6">
                                <strong>Status</strong><br>
                                <span class="badge <?php echo $student_registration['status'] == 'frozen' ? 'status-frozen' : 'status-saved'; ?>">
                                    <?php echo ucfirst($student_registration['status']); ?>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Academic Data Card -->
                <?php if ($academic_data): ?>
                <div class="card academic-card">
                    <div class="card-header bg-warning text-dark">
                        <h5 class="mb-0">
                            <i class="fas fa-chart-line me-2"></i>Academic Information
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-6">
                                <strong>CGPA:</strong><br>
                                <span class="h4 text-primary">
                                    <?php echo $academic_data['cgpa'] ? number_format($academic_data['cgpa'], 2) : 'N/A'; ?>
                                </span>
                            </div>
                            <div class="col-6">
                                <strong>Backlogs:</strong><br>
                                <span class="h4 <?php echo $academic_data['backlogs'] > 0 ? 'text-danger' : 'text-success'; ?>">
                                    <?php echo $academic_data['backlogs']; ?>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <!-- Allotment Result Card - UPDATED WITH PUBLICATION CHECK -->
                <?php if ($allotment_result && $results_published): ?>
                <div class="card allotment-success">
                    <div class="card-body text-center text-white">
                        <i class="fas fa-trophy fa-3x mb-3"></i>
                        <h4>Subject Allotted!</h4>
                        <h5><?php echo htmlspecialchars($allotment_result['subject_name']); ?></h5>
                        <p class="mb-2">
                            <strong>Subject Code:</strong> <?php echo htmlspecialchars($allotment_result['subject_code']); ?>
                        </p>
                        <?php if ($allotment_result['allotment_reason']): ?>
                        <p class="mb-0">
                            <small><strong>Allotment Basis:</strong> <?php echo htmlspecialchars($allotment_result['allotment_reason']); ?></small>
                        </p>
                        <?php endif; ?>
                    </div>
                </div>
                <?php elseif ($results_pending_publication): ?>
                <!-- Results pending publication message -->
                <div class="card" style="border-left: 5px solid #ffc107;">
                    <div class="card-body text-center">
                        <i class="fas fa-clock fa-3x mb-3 text-warning"></i>
                        <h5>Results Under Review</h5>
                        <p class="text-muted mb-0">
                            Your allotment has been processed and is currently under administrative review. 
                            Results will be published soon. Please check back later.
                        </p>
                        <small class="text-muted">
                            <i class="fas fa-info-circle me-1"></i>
                            You will be notified once results are officially published
                        </small>
                    </div>
                </div>
                <?php endif; ?>
            </div>

            <!-- Right Column -->
            <div class="col-lg-8">
                <!-- Priority Selection Card -->
                <div class="card priority-card">
                    <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="fas fa-list-ol me-2"></i>Subject Priority Selection
                        </h5>
                        <?php if ($student_registration['status'] != 'frozen' && !$allotment_result && !$results_published): ?>
                        <button type="button" class="btn btn-light btn-sm" onclick="freezePreferences()">
                            <i class="fas fa-lock me-1"></i>Freeze Preferences
                        </button>
                        <?php endif; ?>
                    </div>
                    <div class="card-body">
                        <?php if ($student_programme): ?>
                        <div class="programme-info">
                            <i class="fas fa-info-circle me-2"></i>
                            <strong>Showing subjects available for your programme:</strong> <?php echo htmlspecialchars($student_programme); ?>
                        </div>
                        <?php endif; ?>

                        <?php if ($student_registration['status'] == 'frozen'): ?>
                            <div class="alert alert-warning">
                                <i class="fas fa-lock me-2"></i>
                                Your preferences are frozen and cannot be modified. 
                                <?php if ($student_registration['frozen_at']): ?>
                                    Frozen on <?php echo date('d M Y, h:i A', strtotime($student_registration['frozen_at'])); ?>
                                <?php endif; ?>
                            </div>
                        <?php elseif ($results_published && $allotment_result): ?>
                            <div class="alert alert-info">
                                <i class="fas fa-info-circle me-2"></i>
                                Subject allotment completed. You have been allotted: <strong><?php echo htmlspecialchars($allotment_result['subject_name']); ?></strong>
                            </div>
                        <?php endif; ?>

                        <?php if (!$results_published || !$allotment_result): ?>
                        <form method="POST" action="" id="priorityForm">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <input type="hidden" name="form_token" value="<?php echo $form_token; ?>">
                            <input type="hidden" name="action" value="save_priorities">
                            
                            <?php if (empty($available_subjects)): ?>
                                <div class="alert alert-info text-center">
                                    <i class="fas fa-info-circle fa-2x mb-2"></i>
                                    <p>No subjects available for your programme (<?php echo htmlspecialchars($student_programme ?? 'Unknown'); ?>) in this pool.</p>
                                </div>
                            <?php else: ?>
                                <div class="row">
                                    <?php foreach ($available_subjects as $subject): ?>
                                    <div class="col-md-6">
                                        <div class="subject-item">
                                            <div class="d-flex justify-content-between align-items-start">
                                                <div class="flex-grow-1">
                                                    <h6 class="mb-2">
                                                        <strong><?php echo htmlspecialchars($subject['subject_name']); ?></strong>
                                                    </h6>
                                                    <p class="text-muted small mb-2">
                                                        <i class="fas fa-code me-1"></i>
                                                        <?php echo htmlspecialchars($subject['subject_code']); ?>
                                                    </p>
                                                    <p class="text-muted small mb-0">
                                                        <i class="fas fa-users me-1"></i>
                                                        Intake: <?php echo $subject['intake']; ?>
                                                    </p>
                                                </div>
                                                <div>
                                                    <label class="form-label small">Priority</label>
                                                    <input type="number" 
                                                           class="form-control priority-input text-center" 
                                                           name="subject_priority[<?php echo htmlspecialchars($subject['subject_code']); ?>]"
                                                           min="1" 
                                                           max="<?php echo count($available_subjects); ?>" 
                                                           value="<?php echo $current_priorities[$subject['subject_code']] ?? ''; ?>"
                                                           <?php echo ($student_registration['status'] == 'frozen' || ($results_published && $allotment_result)) ? 'readonly' : ''; ?>
                                                           placeholder="1-<?php echo count($available_subjects); ?>"
                                                           required>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <?php endforeach; ?>
                                </div>

                                <?php if ($student_registration['status'] != 'frozen' && (!$results_published || !$allotment_result)): ?>
                                <div class="row mt-3">
                                    <div class="col-12">
                                        <div class="alert alert-warning">
                                            <i class="fas fa-lightbulb me-2"></i>
                                            <strong>IMPORTANT INSTRUCTIONS:</strong>
                                            <ul class="mb-0 mt-2">
                                                <li>You have <strong><?php echo count($available_subjects); ?> subjects</strong> available</li>
                                                <li><strong class="text-danger">You MUST set priorities for ALL <?php echo count($available_subjects); ?> subjects</strong></li>
                                                <li>Use priority numbers from <strong>1 to <?php echo count($available_subjects); ?></strong> only</li>
                                                <li>1 = highest priority, <?php echo count($available_subjects); ?> = lowest priority</li>
                                                <li><strong class="text-danger">Each priority number must be unique (no duplicates allowed)</strong></li>
                                                <li><strong class="text-danger">You cannot leave any subject without a priority</strong></li>
                                                <li>You can save multiple times before freezing</li>
                                                <li>Once frozen, you cannot modify your selections</li>
                                                <li class="text-primary"><strong>Only subjects available for your programme (<?php echo htmlspecialchars($student_programme ?? 'Unknown'); ?>) are shown</strong></li>
                                            </ul>
                                        </div>
                                        
                                        <!-- Progress Indicator -->
                                        <div class="progress-container" id="priorityProgress">
                                            <div class="d-flex justify-content-between align-items-center mb-2">
                                                <strong>Priority Setting Progress:</strong>
                                                <span class="badge bg-secondary" id="progressBadge">0/<?php echo count($available_subjects); ?></span>
                                            </div>
                                            <div class="progress">
                                                <div class="progress-bar bg-warning" id="progressBar" style="width: 0%" role="progressbar">0%</div>
                                            </div>
                                            <small class="text-danger" id="progressText">Please set priorities for all <?php echo count($available_subjects); ?> subjects</small>
                                        </div>
                                        
                                        <div class="d-grid gap-2 d-md-flex justify-content-md-end mt-3">
                                            <button type="submit" class="btn btn-success me-md-2 disabled" id="saveBtn" disabled>
                                                <i class="fas fa-save me-2"></i>Save Priorities
                                            </button>
                                            <button type="button" class="btn btn-warning" onclick="clearPriorities()">
                                                <i class="fas fa-times me-2"></i>Clear All
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                <?php endif; ?>
                            <?php endif; ?>
                        </form>
                        <?php endif; ?>

                        <!-- Current Priorities Display -->
                        <?php if (!empty($current_priorities)): ?>
                        <div class="mt-4">
                            <h6><i class="fas fa-list me-2"></i>Your Current Priorities:</h6>
                            <div class="row">
                                <?php 
                                $sorted_priorities = $current_priorities;
                                asort($sorted_priorities);
                                foreach ($sorted_priorities as $subject_code => $priority): 
                                    $subject_name = '';
                                    foreach ($available_subjects as $subject) {
                                        if ($subject['subject_code'] == $subject_code) {
                                            $subject_name = $subject['subject_name'];
                                            break;
                                        }
                                    }
                                ?>
                                <div class="col-md-6 mb-2">
                                    <div class="d-flex justify-content-between align-items-center bg-light p-2 rounded">
                                        <span><strong><?php echo $priority; ?>.</strong> <?php echo htmlspecialchars($subject_name); ?></span>
                                        <small class="text-muted"><?php echo htmlspecialchars($subject_code); ?></small>
                                    </div>
                                </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Freeze Confirmation Modal -->
    <div class="modal fade" id="freezeModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-lock me-2"></i>Freeze Preferences
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        <strong>Warning!</strong> Once you freeze your preferences, you will not be able to modify them.
                    </div>
                    <p>Are you sure you want to freeze your current subject priorities?</p>
                    <div id="freezePreview" class="mt-3">
                        <!-- Preview will be populated by JavaScript -->
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <form method="POST" action="" style="display: inline;">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <input type="hidden" name="form_token" value="<?php echo generate_token(); ?>">
                        <input type="hidden" name="action" value="freeze_preferences">
                        <button type="submit" class="btn btn-danger" id="confirmFreezeBtn" disabled>
                            <i class="fas fa-lock me-2"></i>Yes, Freeze Preferences
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const totalSubjects = <?php echo count($available_subjects); ?>;
        
        // Enhanced real-time validation
        function validatePriorities() {
            const priorityInputs = document.querySelectorAll('input[name^="subject_priority"]');
            const usedPriorities = [];
            let hasError = false;
            let filledCount = 0;
            
            priorityInputs.forEach(input => {
                const value = parseInt(input.value);
                
                // Reset styling
                input.classList.remove('is-invalid', 'is-valid');
                
                if (value && value > 0) {
                    filledCount++;
                    if (value > totalSubjects) {
                        input.classList.add('is-invalid');
                        input.title = `Maximum priority is ${totalSubjects}`;
                        hasError = true;
                    } else if (usedPriorities.includes(value)) {
                        input.classList.add('is-invalid');
                        input.title = `Priority ${value} is already used`;
                        hasError = true;
                    } else {
                        input.classList.add('is-valid');
                        input.title = '';
                        usedPriorities.push(value);
                    }
                } else {
                    // Empty input - show as invalid
                    input.classList.add('is-invalid');
                    input.title = 'Priority required for this subject';
                    hasError = true;
                }
            });
            
            // Update progress indicator
            updateProgressIndicator(filledCount, totalSubjects, hasError);
            
            // Update submit button state
            const submitBtn = document.getElementById('saveBtn');
            if (submitBtn) {
                if (hasError || filledCount !== totalSubjects) {
                    submitBtn.classList.add('disabled');
                    submitBtn.disabled = true;
                    if (filledCount !== totalSubjects) {
                        submitBtn.title = `Set priorities for all ${totalSubjects} subjects (${filledCount}/${totalSubjects} done)`;
                    } else {
                        submitBtn.title = 'Fix priority errors before saving';
                    }
                } else {
                    submitBtn.classList.remove('disabled');
                    submitBtn.disabled = false;
                    submitBtn.title = '';
                }
            }
        }

        // Update progress indicator
        function updateProgressIndicator(filled, total, hasError) {
            const percentage = (filled / total) * 100;
            const isComplete = filled === total && !hasError;
            
            const progressBar = document.getElementById('progressBar');
            const progressBadge = document.getElementById('progressBadge');
            const progressText = document.getElementById('progressText');
            
            if (progressBar) {
                progressBar.style.width = percentage + '%';
                progressBar.textContent = Math.round(percentage) + '%';
                progressBar.className = isComplete ? 'progress-bar bg-success' : 'progress-bar bg-warning';
            }
            
            if (progressBadge) {
                progressBadge.textContent = `${filled}/${total}`;
                progressBadge.className = isComplete ? 'badge bg-success' : 'badge bg-warning';
            }
            
            if (progressText) {
                if (isComplete) {
                    progressText.textContent = 'All subjects have been prioritized! You can now save.';
                    progressText.className = 'text-success';
                } else if (hasError) {
                    progressText.textContent = 'Please fix priority errors before continuing.';
                    progressText.className = 'text-danger';
                } else {
                    progressText.textContent = `Please set priorities for ${total - filled} more subject(s)`;
                    progressText.className = 'text-danger';
                }
            }
        }
        
        // Add real-time validation to all priority inputs
        document.addEventListener('DOMContentLoaded', function() {
            const priorityInputs = document.querySelectorAll('input[name^="subject_priority"]');
            priorityInputs.forEach(input => {
                input.addEventListener('input', validatePriorities);
                input.addEventListener('change', validatePriorities);
            });
            
            // Initial validation
            validatePriorities();
        });

        function freezePreferences() {
            // Check if all priorities are set
            const priorityInputs = document.querySelectorAll('input[name^="subject_priority"]');
            let allSet = true;
            const currentPriorities = [];
            
            priorityInputs.forEach(input => {
                const value = parseInt(input.value);
                if (!value || value <= 0) {
                    allSet = false;
                } else {
                    const subjectCode = input.name.match(/\[(.*?)\]/)[1];
                    const subjectName = input.closest('.subject-item').querySelector('h6 strong').textContent;
                    currentPriorities.push({priority: value, code: subjectCode, name: subjectName});
                }
            });
            
            if (!allSet) {
                alert('Please set priorities for ALL subjects before freezing.');
                return;
            }
            
            // Sort and show preview
            currentPriorities.sort((a, b) => a.priority - b.priority);
            const preview = document.getElementById('freezePreview');
            let previewHTML = '<h6>Your Final Priority Order:</h6><ol>';
            currentPriorities.forEach(item => {
                previewHTML += `<li><strong>${item.name}</strong> (${item.code})</li>`;
            });
            previewHTML += '</ol>';
            preview.innerHTML = previewHTML;
            
            // Enable freeze button
            document.getElementById('confirmFreezeBtn').disabled = false;
            
            const modal = new bootstrap.Modal(document.getElementById('freezeModal'));
            modal.show();
        }

        function clearPriorities() {
            if (confirm('Are you sure you want to clear all priorities?')) {
                const priorityInputs = document.querySelectorAll('input[name^="subject_priority"]');
                priorityInputs.forEach(input => {
                    input.value = '';
                    input.classList.remove('is-invalid', 'is-valid');
                });
                validatePriorities();
            }
        }

        function refreshPage() {
            window.location.reload();
        }

        // Enhanced Form validation
        document.getElementById('priorityForm').addEventListener('submit', function(e) {
            const priorityInputs = document.querySelectorAll('input[name^="subject_priority"]');
            const priorities = [];
            let hasError = false;

            // Collect all priority values
            priorityInputs.forEach(input => {
                const value = parseInt(input.value);
                if (value && value > 0) {
                    // Check if priority is within valid range
                    if (value > totalSubjects) {
                        alert(`Priority must be between 1 and ${totalSubjects}. You entered ${value}.`);
                        input.focus();
                        hasError = true;
                        return;
                    }
                    
                    // Check for duplicates
                    if (priorities.includes(value)) {
                        alert(`Duplicate priority ${value} found! Each priority number must be unique.`);
                        input.focus();
                        hasError = true;
                        return;
                    }
                    priorities.push(value);
                } else {
                    alert('All subjects must have a priority set.');
                    input.focus();
                    hasError = true;
                    return;
                }
            });

            if (hasError) {
                e.preventDefault();
                return;
            }

            // Check if all subjects have priorities
            if (priorities.length !== totalSubjects) {
                const missing = totalSubjects - priorities.length;
                alert(`You must set priorities for ALL ${totalSubjects} subjects. You have ${missing} subject(s) without priorities.`);
                e.preventDefault();
                return;
            }

            // Check if priorities are sequential from 1 to totalSubjects
            const sortedPriorities = [...priorities].sort((a, b) => a - b);
            for (let i = 0; i < sortedPriorities.length; i++) {
                if (sortedPriorities[i] !== i + 1) {
                    alert(`You must use all priority numbers from 1 to ${totalSubjects} without gaps. Missing priority: ${i + 1}`);
                    e.preventDefault();
                    return;
                }
            }

            // Show loading state
            const submitBtn = this.querySelector('button[type="submit"]');
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Saving...';
            submitBtn.disabled = true;
        });

        // Auto-refresh every 10 minutes
        setTimeout(function() {
            window.location.reload();
        }, 600000);

        // Prevent form resubmission on page refresh
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
    </script>
</body>
</html>