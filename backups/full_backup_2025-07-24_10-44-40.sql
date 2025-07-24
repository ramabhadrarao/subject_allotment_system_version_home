-- Subject Allotment System Full Database Backup
-- Generated on: 2025-07-24 10:44:40
-- Database: subject_allotment_system

SET FOREIGN_KEY_CHECKS = 0;
SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';
SET AUTOCOMMIT = 0;
START TRANSACTION;

-- Structure for table `admin`
DROP TABLE IF EXISTS `admin`;
CREATE TABLE `admin` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Data for table `admin`
INSERT INTO `admin` (`id`, `username`, `password`, `email`, `name`, `created_at`, `updated_at`) VALUES ('1', 'admin', 'e731ef763d9aa305d86ccac6cc3e3674', 'admin@swarnandhra.ac.in', 'System Administrator', '2025-07-23 13:06:06', '2025-07-23 13:06:06');
INSERT INTO `admin` (`id`, `username`, `password`, `email`, `name`, `created_at`, `updated_at`) VALUES ('2', 'subjectadmin', 'e731ef763d9aa305d86ccac6cc3e3674', 'subject.admin@swarnandhra.ac.in', 'Subject Pool Administrator', '2025-07-23 13:06:06', '2025-07-23 13:06:06');

-- Structure for table `subject_pools`
DROP TABLE IF EXISTS `subject_pools`;
CREATE TABLE `subject_pools` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `pool_name` varchar(100) NOT NULL,
  `subject_code` varchar(20) NOT NULL,
  `subject_name` varchar(200) NOT NULL,
  `intake` int(11) NOT NULL,
  `allowed_programmes` text DEFAULT NULL,
  `batch` varchar(20) DEFAULT NULL,
  `semester` varchar(50) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_by` int(11) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `created_ip` varchar(45) DEFAULT NULL,
  `updated_ip` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `created_by` (`created_by`),
  CONSTRAINT `subject_pools_ibfk_1` FOREIGN KEY (`created_by`) REFERENCES `admin` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Data for table `subject_pools`
INSERT INTO `subject_pools` (`id`, `pool_name`, `subject_code`, `subject_name`, `intake`, `allowed_programmes`, `batch`, `semester`, `is_active`, `created_by`, `created_at`, `updated_at`, `created_ip`, `updated_ip`) VALUES ('1', 'A', '20CE6O02', 'Test', '5', '[\"B.Tech - CSEBS\"]', '2023-2027', 'Fifth Semester', '0', '1', '2025-07-23 13:37:52', '2025-07-23 16:15:47', '43.250.40.130', '43.250.40.130');
INSERT INTO `subject_pools` (`id`, `pool_name`, `subject_code`, `subject_name`, `intake`, `allowed_programmes`, `batch`, `semester`, `is_active`, `created_by`, `created_at`, `updated_at`, `created_ip`, `updated_ip`) VALUES ('2', 'A', '20EC6O01', 'JAVA', '10', '[\"B.Tech - Civil\",\"B.Tech - CSEBS\",\"B.Tech - CSECS\",\"B.Tech - ECE\",\"B.Tech - EEE\",\"B.Tech - Mech\"]', '2023-2027', 'Fifth Semester', '0', '1', '2025-07-23 13:40:16', '2025-07-23 16:15:45', '43.250.40.130', '43.250.40.130');
INSERT INTO `subject_pools` (`id`, `pool_name`, `subject_code`, `subject_name`, `intake`, `allowed_programmes`, `batch`, `semester`, `is_active`, `created_by`, `created_at`, `updated_at`, `created_ip`, `updated_ip`) VALUES ('3', 'Subjects Pool 1', '20AML001', 'JAVA', '2', '[\"B.Tech - CSE\",\"B.Tech - CSEBS\"]', '2023-2027', 'Fifth Semester', '0', '1', '2025-07-24 05:48:36', '2025-07-24 10:35:40', '49.37.135.228', '210.212.211.50');
INSERT INTO `subject_pools` (`id`, `pool_name`, `subject_code`, `subject_name`, `intake`, `allowed_programmes`, `batch`, `semester`, `is_active`, `created_by`, `created_at`, `updated_at`, `created_ip`, `updated_ip`) VALUES ('4', 'Subjects Pool 1', '20AML002', 'python', '2', '[\"B.Tech - CSE\",\"B.Tech - CSEBS\"]', '2023-2027', 'Fifth Semester', '0', '1', '2025-07-24 05:49:07', '2025-07-24 10:35:40', '49.37.135.228', '210.212.211.50');
INSERT INTO `subject_pools` (`id`, `pool_name`, `subject_code`, `subject_name`, `intake`, `allowed_programmes`, `batch`, `semester`, `is_active`, `created_by`, `created_at`, `updated_at`, `created_ip`, `updated_ip`) VALUES ('5', 'Subjects Pool 2', '20AML003', 'c plus plus', '2', '[\"B.Tech - ECE\"]', '2023-2027', 'Fifth Semester', '0', '1', '2025-07-24 05:52:12', '2025-07-24 10:35:40', '49.37.135.228', NULL);

-- Structure for table `student_academic_data`
DROP TABLE IF EXISTS `student_academic_data`;
CREATE TABLE `student_academic_data` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `regno` varchar(20) NOT NULL,
  `cgpa` decimal(4,2) DEFAULT NULL,
  `backlogs` int(11) DEFAULT 0,
  `uploaded_by` int(11) DEFAULT NULL,
  `uploaded_at` timestamp NULL DEFAULT current_timestamp(),
  `uploaded_ip` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `regno` (`regno`),
  KEY `uploaded_by` (`uploaded_by`),
  KEY `idx_regno` (`regno`),
  KEY `idx_cgpa` (`cgpa`),
  KEY `idx_backlogs` (`backlogs`),
  CONSTRAINT `student_academic_data_ibfk_1` FOREIGN KEY (`uploaded_by`) REFERENCES `admin` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Structure for table `student_registrations`
DROP TABLE IF EXISTS `student_registrations`;
CREATE TABLE `student_registrations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `regno` varchar(20) NOT NULL,
  `email` varchar(100) NOT NULL,
  `mobile` varchar(15) NOT NULL,
  `pool_id` int(11) NOT NULL,
  `priority_order` text DEFAULT NULL,
  `status` enum('saved','frozen') DEFAULT 'saved',
  `registration_token` varchar(64) DEFAULT NULL,
  `registered_at` timestamp NULL DEFAULT current_timestamp(),
  `frozen_at` timestamp NULL DEFAULT NULL,
  `registration_ip` varchar(45) DEFAULT NULL,
  `last_updated_ip` varchar(45) DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `registration_token` (`registration_token`),
  KEY `idx_regno` (`regno`),
  KEY `idx_pool_id` (`pool_id`),
  KEY `idx_status` (`status`),
  CONSTRAINT `student_registrations_ibfk_1` FOREIGN KEY (`pool_id`) REFERENCES `subject_pools` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Structure for table `subject_allotments`
DROP TABLE IF EXISTS `subject_allotments`;
CREATE TABLE `subject_allotments` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `regno` varchar(20) NOT NULL,
  `pool_id` int(11) NOT NULL,
  `subject_code` varchar(20) NOT NULL,
  `allotment_reason` text DEFAULT NULL,
  `allotment_rank` int(11) DEFAULT NULL,
  `allotted_by` int(11) DEFAULT NULL,
  `allotted_at` timestamp NULL DEFAULT current_timestamp(),
  `allotment_ip` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `allotted_by` (`allotted_by`),
  KEY `idx_regno` (`regno`),
  KEY `idx_pool_id` (`pool_id`),
  KEY `idx_subject_code` (`subject_code`),
  CONSTRAINT `subject_allotments_ibfk_1` FOREIGN KEY (`pool_id`) REFERENCES `subject_pools` (`id`),
  CONSTRAINT `subject_allotments_ibfk_2` FOREIGN KEY (`allotted_by`) REFERENCES `admin` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Structure for table `activity_logs`
DROP TABLE IF EXISTS `activity_logs`;
CREATE TABLE `activity_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_type` enum('admin','student') NOT NULL,
  `user_identifier` varchar(50) NOT NULL,
  `action` varchar(100) NOT NULL,
  `table_name` varchar(50) DEFAULT NULL,
  `record_id` int(11) DEFAULT NULL,
  `old_values` text DEFAULT NULL,
  `new_values` text DEFAULT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` text DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_user_type` (`user_type`),
  KEY `idx_user_identifier` (`user_identifier`),
  KEY `idx_action` (`action`),
  KEY `idx_timestamp` (`timestamp`)
) ENGINE=InnoDB AUTO_INCREMENT=312 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Data for table `activity_logs`
INSERT INTO `activity_logs` (`id`, `user_type`, `user_identifier`, `action`, `table_name`, `record_id`, `old_values`, `new_values`, `ip_address`, `user_agent`, `timestamp`) VALUES ('304', 'admin', 'admin', 'bulk_data_deletion', NULL, NULL, NULL, '{\"action\":\"delete_logs\",\"deleted_counts\":{\"Activity Logs\":13,\"Login Logs\":1,\"Security Logs\":1},\"admin_user\":\"admin\"}', '43.250.40.130', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:38:48');
INSERT INTO `activity_logs` (`id`, `user_type`, `user_identifier`, `action`, `table_name`, `record_id`, `old_values`, `new_values`, `ip_address`, `user_agent`, `timestamp`) VALUES ('305', 'admin', 'admin', 'dashboard_view', NULL, NULL, NULL, NULL, '43.250.40.130', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:38:51');
INSERT INTO `activity_logs` (`id`, `user_type`, `user_identifier`, `action`, `table_name`, `record_id`, `old_values`, `new_values`, `ip_address`, `user_agent`, `timestamp`) VALUES ('306', 'admin', 'admin', 'logout', NULL, NULL, NULL, NULL, '43.250.40.130', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:38:55');
INSERT INTO `activity_logs` (`id`, `user_type`, `user_identifier`, `action`, `table_name`, `record_id`, `old_values`, `new_values`, `ip_address`, `user_agent`, `timestamp`) VALUES ('307', 'admin', 'admin', 'successful_login', NULL, NULL, NULL, NULL, '43.250.40.130', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:39:08');
INSERT INTO `activity_logs` (`id`, `user_type`, `user_identifier`, `action`, `table_name`, `record_id`, `old_values`, `new_values`, `ip_address`, `user_agent`, `timestamp`) VALUES ('308', 'admin', 'admin', 'dashboard_view', NULL, NULL, NULL, NULL, '43.250.40.130', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:39:08');
INSERT INTO `activity_logs` (`id`, `user_type`, `user_identifier`, `action`, `table_name`, `record_id`, `old_values`, `new_values`, `ip_address`, `user_agent`, `timestamp`) VALUES ('309', 'admin', 'admin', 'dashboard_view', NULL, NULL, NULL, NULL, '43.250.40.130', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:41:37');
INSERT INTO `activity_logs` (`id`, `user_type`, `user_identifier`, `action`, `table_name`, `record_id`, `old_values`, `new_values`, `ip_address`, `user_agent`, `timestamp`) VALUES ('310', 'admin', 'admin', 'dashboard_view', NULL, NULL, NULL, NULL, '43.250.40.130', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:41:53');
INSERT INTO `activity_logs` (`id`, `user_type`, `user_identifier`, `action`, `table_name`, `record_id`, `old_values`, `new_values`, `ip_address`, `user_agent`, `timestamp`) VALUES ('311', 'admin', 'admin', 'dashboard_view', NULL, NULL, NULL, NULL, '43.250.40.130', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:41:57');

-- Structure for table `login_logs`
DROP TABLE IF EXISTS `login_logs`;
CREATE TABLE `login_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_type` enum('admin','student') NOT NULL,
  `user_identifier` varchar(50) NOT NULL,
  `action` enum('login','logout','failed_login') NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` text DEFAULT NULL,
  `login_time` timestamp NULL DEFAULT current_timestamp(),
  `logout_time` timestamp NULL DEFAULT NULL,
  `session_duration` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_user_type` (`user_type`),
  KEY `idx_user_identifier` (`user_identifier`),
  KEY `idx_action` (`action`),
  KEY `idx_login_time` (`login_time`)
) ENGINE=InnoDB AUTO_INCREMENT=65 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Data for table `login_logs`
INSERT INTO `login_logs` (`id`, `user_type`, `user_identifier`, `action`, `ip_address`, `user_agent`, `login_time`, `logout_time`, `session_duration`) VALUES ('63', 'admin', 'admin', 'logout', '43.250.40.130', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:38:55', NULL, NULL);
INSERT INTO `login_logs` (`id`, `user_type`, `user_identifier`, `action`, `ip_address`, `user_agent`, `login_time`, `logout_time`, `session_duration`) VALUES ('64', 'admin', 'admin', 'login', '43.250.40.130', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:39:08', NULL, NULL);

-- Structure for table `security_logs`
DROP TABLE IF EXISTS `security_logs`;
CREATE TABLE `security_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_type` varchar(50) NOT NULL,
  `severity` enum('low','medium','high','critical') NOT NULL,
  `user_identifier` varchar(50) DEFAULT NULL,
  `ip_address` varchar(45) NOT NULL,
  `description` text NOT NULL,
  `user_agent` text DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_event_type` (`event_type`),
  KEY `idx_severity` (`severity`),
  KEY `idx_timestamp` (`timestamp`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Data for table `security_logs`
INSERT INTO `security_logs` (`id`, `event_type`, `severity`, `user_identifier`, `ip_address`, `description`, `user_agent`, `timestamp`) VALUES ('6', 'bulk_data_deletion', 'high', 'admin', '43.250.40.130', 'Admin admin performed bulk deletion: delete_logs', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:38:48');

-- Structure for table `user_sessions`
DROP TABLE IF EXISTS `user_sessions`;
CREATE TABLE `user_sessions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `session_id` varchar(128) NOT NULL,
  `user_type` enum('admin','student') NOT NULL,
  `user_identifier` varchar(50) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `last_activity` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `expires_at` timestamp NOT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `session_id` (`session_id`),
  KEY `idx_session_id` (`session_id`),
  KEY `idx_user_identifier` (`user_identifier`),
  KEY `idx_expires_at` (`expires_at`)
) ENGINE=InnoDB AUTO_INCREMENT=33 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Data for table `user_sessions`
INSERT INTO `user_sessions` (`id`, `session_id`, `user_type`, `user_identifier`, `ip_address`, `user_agent`, `created_at`, `last_activity`, `expires_at`, `is_active`) VALUES ('31', 'r0o1ugth1h8bbahk9dk1q1e560', 'admin', 'admin', '43.250.40.130', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:36:02', '2025-07-24 10:38:55', '2025-07-24 11:08:51', '0');
INSERT INTO `user_sessions` (`id`, `session_id`, `user_type`, `user_identifier`, `ip_address`, `user_agent`, `created_at`, `last_activity`, `expires_at`, `is_active`) VALUES ('32', 'qoceqn3v75kgr5kh3jkvsjuvfr', 'admin', 'admin', '43.250.40.130', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', '2025-07-24 10:39:08', '2025-07-24 10:44:40', '2025-07-24 11:14:40', '1');

-- Structure for table `form_submissions`
DROP TABLE IF EXISTS `form_submissions`;
CREATE TABLE `form_submissions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `form_token` varchar(64) NOT NULL,
  `user_type` enum('admin','student') NOT NULL,
  `user_identifier` varchar(50) NOT NULL,
  `form_type` varchar(50) NOT NULL,
  `submitted_at` timestamp NULL DEFAULT current_timestamp(),
  `ip_address` varchar(45) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `form_token` (`form_token`),
  KEY `idx_form_token` (`form_token`),
  KEY `idx_user_identifier` (`user_identifier`)
) ENGINE=InnoDB AUTO_INCREMENT=66 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Data for table `form_submissions`
INSERT INTO `form_submissions` (`id`, `form_token`, `user_type`, `user_identifier`, `form_type`, `submitted_at`, `ip_address`) VALUES ('63', 'ef4930601a9950ad9490567864eba78756781f4c3614701aaf15462e95346cdd', 'admin', 'admin', 'create_backup', '2025-07-24 10:37:47', '43.250.40.130');
INSERT INTO `form_submissions` (`id`, `form_token`, `user_type`, `user_identifier`, `form_type`, `submitted_at`, `ip_address`) VALUES ('64', 'adb3b846ad378a63a89aa3559a55c3059e968daeba0d14309a26351c4f9297e6', 'admin', 'admin', 'delete_data_operation', '2025-07-24 10:38:48', '43.250.40.130');
INSERT INTO `form_submissions` (`id`, `form_token`, `user_type`, `user_identifier`, `form_type`, `submitted_at`, `ip_address`) VALUES ('65', '70b3f10621ab352f47a72298ca631bfd7b0b1fd62148d9477d91428e1f0cac67', 'admin', 'admin', 'create_backup', '2025-07-24 10:39:14', '43.250.40.130');

COMMIT;
SET FOREIGN_KEY_CHECKS = 1;
