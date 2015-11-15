CREATE TABLE `cert` (
  `sha256` char(64) NOT NULL,
  `parent` char(64) DEFAULT NULL,
  `birth` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `pulse` timestamp NULL DEFAULT NULL,
  `content` text NOT NULL,
  PRIMARY KEY (`sha256`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `connections` (
  `domain` varchar(255) NOT NULL,
  `port` int(10) unsigned NOT NULL,
  `sha256` char(64) NOT NULL,
  `birth` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `pulse` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`domain`,`port`),
  KEY `sha256` (`sha256`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
