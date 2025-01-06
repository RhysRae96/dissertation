-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Oct 28, 2024 at 04:20 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `dissertation`
--

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `user_id` varchar(36) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `is_email_verified` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`user_id`, `username`, `email`, `password`, `is_email_verified`) VALUES
('28ad8f53-f343-44a0-b164-1a9b90d0c607', 'test', 'hawkinghirt@gmail.com', '$2y$10$n.a.3uTyWbHjfpCtZIvsQ.Wqzecz1Ytd/Ez9bBW/ho98eCJ8M17jy', 0),
('52fedb11-f29e-47c5-a71d-ae7c9a137335', 'test', 'rhysjamesrae@gmail.com', '$2y$10$szsh1P/4B3rmorPKtgtzF./Kg9EJvxXukT76hMGYTtZnrKpfSriGa', 0),
('8c99d4e4-7976-4d30-9a23-1e980ddafc83', 'VJG', 'johndoe@gmail.com', '$2y$10$JigyBPdVnrXinDbmBxFTNuhvDzSDrodH28leLmzQt0Sf80rkv9OI.', 0),
('b96c3135-dee2-486f-b44d-0dc809bd67e6', 'Chuck', 'Plebnuts@gmail.com', '$2y$10$yASA3.VapvIG8pNyDXju7Od8vdTv/O3vesNRVoxN3w9kGrYOjh/ha', 0),
('bd20cb42-2cf5-4832-8049-108116541b03', 'rhys', 'rhysjamesrae@gmail.com', '$2y$10$p1NG5/uYW0sbfMll3TnYBOWCMerP69bdYBeiLwohmOlha1rNXohsS', 0);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`user_id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
