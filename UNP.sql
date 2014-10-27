-- phpMyAdmin SQL Dump
-- version 4.0.10deb1
-- http://www.phpmyadmin.net
--
-- Machine: localhost
-- Genereertijd: 26 okt 2014 om 12:11
-- Serverversie: 5.5.40-0ubuntu0.14.04.1
-- PHP-versie: 5.5.9-1ubuntu4.4

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Databank: `UNP`
--

-- --------------------------------------------------------

--
-- Tabelstructuur voor tabel `ETH`
--

CREATE TABLE IF NOT EXISTS `ETH` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Datetime` varchar(30) NOT NULL,
  `Dest_mac` varchar(17) NOT NULL,
  `Source_mac` varchar(17) NOT NULL,
  `Protocol` int(11) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Tabelstructuur voor tabel `ICMP`
--

CREATE TABLE IF NOT EXISTS `ICMP` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Datetime` varchar(30) NOT NULL,
  `Type` int(11) NOT NULL,
  `Code` int(11) NOT NULL,
  `Checksum` int(11) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Tabelstructuur voor tabel `IP`
--

CREATE TABLE IF NOT EXISTS `IP` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Datetime` varchar(30) NOT NULL,
  `Version` int(11) NOT NULL,
  `IHL` int(11) NOT NULL,
  `TTL` int(11) NOT NULL,
  `Protocol` int(11) NOT NULL,
  `Source_addr` varchar(45) NOT NULL,
  `Dest_addr` varchar(45) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Tabelstructuur voor tabel `TCP`
--

CREATE TABLE IF NOT EXISTS `TCP` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Datetime` varchar(30) NOT NULL,
  `Source_port` int(11) NOT NULL,
  `Desc_port` int(11) NOT NULL,
  `Sequence` int(11) NOT NULL,
  `Acknowledge` int(11) NOT NULL,
  `Length` int(11) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Tabelstructuur voor tabel `UDP`
--

CREATE TABLE IF NOT EXISTS `UDP` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Datetime` varchar(30) NOT NULL,
  `Source_port` int(11) NOT NULL,
  `Dest_port` int(11) NOT NULL,
  `Length` int(11) NOT NULL,
  `Checksum` int(11) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
