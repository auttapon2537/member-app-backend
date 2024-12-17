-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: db
-- Generation Time: Dec 17, 2024 at 11:29 AM
-- Server version: 8.0.40
-- PHP Version: 8.2.8

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `member`
--

-- --------------------------------------------------------

--
-- Table structure for table `privileges`
--

CREATE TABLE `privileges` (
  `id` int NOT NULL,
  `product_name` varchar(255) NOT NULL,
  `image` varchar(255) DEFAULT NULL,
  `points_required` int NOT NULL,
  `expiration_date` date NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Dumping data for table `privileges`
--

INSERT INTO `privileges` (`id`, `product_name`, `image`, `points_required`, `expiration_date`) VALUES
(1, 'Gift Card $10', '/public/001.png', 1000, '2025-12-31'),
(2, 'Gift Card $20', '/public/002.png', 2000, '2025-12-31'),
(3, 'Bluetooth Headphones', '/public/003.png', 3000, '2025-12-31'),
(4, 'Smartwatch', '/public/004.png', 5000, '2025-12-31'),
(5, 'Laptop Sleeve', '/public/005.png', 1500, '2025-12-31'),
(6, 'Portable Speaker', '/public/006.png', 2500, '2025-12-31'),
(7, 'Power Bank 10000mAh', '/public/007.png', 1800, '2025-12-31'),
(8, 'Wireless Mouse', '/public/008.png', 1200, '2025-12-31'),
(9, 'USB Flash Drive 64GB', '/public/009.png', 1300, '2025-12-31'),
(10, 'Gaming Chair', '/public/010.png', 8000, '2025-12-31'),
(11, 'Smartphone Case', '/public/011.png', 1000, '2025-12-31'),
(12, 'Tablet Stand', '/public/012.png', 1600, '2025-12-31'),
(13, 'Travel Backpack', '/public/013.png', 2000, '2025-12-31'),
(14, 'Electric Kettle', '/public/014.png', 2200, '2025-12-31'),
(15, 'Coffee Maker', '/public/015.png', 3000, '2025-12-31'),
(16, 'Fitness Tracker', '/public/016.png', 3500, '2025-12-31'),
(17, '4K TV', '/public/017.png', 10000, '2025-12-31'),
(18, 'Air Fryer', '/public/018.png', 7000, '2025-12-31'),
(19, 'Smart Home Hub', '/public/019.png', 6000, '2025-12-31'),
(20, 'Gaming Console', '/public/020.png', 12000, '2025-12-31');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int NOT NULL,
  `fullname` varchar(255) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `points` int NOT NULL DEFAULT '0',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `fullname`, `username`, `password`, `points`, `created_at`) VALUES
(1, 'Auttapon Khoeyputsa', 'admin', '$2a$10$Cy0EOw46k9CHLyCUtUppHuCF3nA1cJCNHUOSM/OL/uqjp6GNOj9YO', 2500, '2024-12-16 16:19:36'),
(6, 'Auttapon Khoeyputsa', 'user01', '$2a$10$PwWSYvhucz.gzka7S9iHV.ZbdOaYR2njOeVa5MF2vMJa2yXCx1StG', 10000, '2024-12-16 16:32:17'),
(8, 'Miyamoto Hayato', 'user02', '$2a$10$ZJJTq59MvN351NluOXUqFe08wzysO7Z6O5l44m7PFqsT/vVj2ZYo6', 10000, '2024-12-16 16:41:42');

-- --------------------------------------------------------

--
-- Table structure for table `users_privileges_map`
--

CREATE TABLE `users_privileges_map` (
  `id` int NOT NULL,
  `user_id` int NOT NULL,
  `privilege_id` int NOT NULL,
  `points_redeemed` int NOT NULL,
  `redeemed_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Dumping data for table `users_privileges_map`
--

INSERT INTO `users_privileges_map` (`id`, `user_id`, `privilege_id`, `points_redeemed`, `redeemed_at`) VALUES
(1, 1, 5, 1500, '2024-12-16 17:34:44'),
(2, 1, 2, 2000, '2024-12-17 09:11:19'),
(3, 1, 13, 2000, '2024-12-17 09:29:37'),
(4, 1, 11, 1000, '2024-12-17 09:31:26'),
(5, 1, 1, 1000, '2024-12-17 10:22:28');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `privileges`
--
ALTER TABLE `privileges`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `users_privileges_map`
--
ALTER TABLE `users_privileges_map`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `privilege_id` (`privilege_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `privileges`
--
ALTER TABLE `privileges`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=21;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `users_privileges_map`
--
ALTER TABLE `users_privileges_map`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `users_privileges_map`
--
ALTER TABLE `users_privileges_map`
  ADD CONSTRAINT `users_privileges_map_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `users_privileges_map_ibfk_2` FOREIGN KEY (`privilege_id`) REFERENCES `privileges` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
