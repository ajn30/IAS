DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    name TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    address TEXT NOT NULL,
    social_security_number TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=1;

DROP TABLE IF EXISTS salary_data;

CREATE TABLE salary_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    base_salary TEXT NOT NULL,
    bonus TEXT NOT NULL,
    tax_rate TEXT NOT NULL,
    encrypted_total TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB AUTO_INCREMENT=1;

