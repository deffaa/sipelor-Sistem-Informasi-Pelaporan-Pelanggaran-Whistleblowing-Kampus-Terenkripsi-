-- phpMyAdmin SQL Dump
-- version 6.0.0-dev+20261123.5add5a93ad
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Nov 25, 2026 at 05:14 PM
-- Server version: 8.4.3
-- PHP Version: 8.4.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `sipelor_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `encrypted_reports`
--
CREATE TABLE `encrypted_reports` (
  `id` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `report_code` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ciphertext` longtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `encrypted_aes_key` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `iv_base64` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `cipher_algo` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'AES-256-CBC + RSA-2048',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `encrypted_reports`
--

INSERT INTO `encrypted_reports` (`id`, `report_code`, `ciphertext`, `encrypted_aes_key`, `iv_base64`, `cipher_algo`, `created_at`) VALUES
('1A8V8GWxAbbqcvmmo97f6A==', 'EfU6Q/eFTC0RvuT1s+NHiw==', 'Gkr0CBDvi/CV+YYZ3AQ3CfDYhK8QcqfM1sYJGA6CPH1GKcpJ/Ig9YfygPksY0Ig0WyhOKult0qtD70dKcWQr5pvVXFL/Qhy9ZrvLV5Luow3vLJtWDipDF9XfRRJOXWE9759rGNOl7Z4HD+wSS9z/Q3Ek2bwrGvSItIT2cphOkMAEj0KFSO+NzP9rVZrJScFWsZX10TSE+tvK3P/TmegKW+A16h4sGdo6CRK5WLtDKDjer/KI9lLK7PHkqQR7VJHGUZ0n+24GWF1P4dllnsdrSVvU7eQGngZCHdQAuk1Hj8n574AmQwDYggdJnzoe/fc+F2hgmgTazt0IBJlM+V9rCA==', 'UubciJqPc5+T/mLQqMvf80TX9kjfOTXchnB7WKeNWUnNlL5CICpaoNnbrI+Mk3Ailr7vYiAgxQVwh27x4bKHeOPVrPZgeBL59EHHwBrsmC3VQ0lGWOSDpEz4yT2W5u5UaPc1/Xtkg9qhNB5aP9d0a8a7v1rnJWPvE0xqectdEXt5i6+qJiTjbPf0G4F5qtRFu/lHMBF/ia0aAJCwvcLaJ1YVtgg0iZBkQpwJRze8cgbPr0OR+1Gcaf6u2RN79A8kr5SKmanEdIcOU9ycQ5dThMJnSFZtfSucSC6wMwEv196e7v1INB4x7lxbb750gf8eUEogCF3RqauV+EEFqgIYkg==', '2ZkfVsMO8dXFkYEETeE11A==', 'AES-256-CBC + RSA-2048', '2026-11-25 16:53:04');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `encrypted_reports`
--
ALTER TABLE `encrypted_reports`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `report_code` (`report_code`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
