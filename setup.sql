CREATE USER 'user_safe'@'localhost' IDENTIFIED BY 'mon_mot_de_passe_secret';
GRANT SELECT, INSERT, UPDATE ON ma_base_de_donnees.* TO 'user_safe'@'localhost';
FLUSH PRIVILEGES;
