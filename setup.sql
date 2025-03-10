-- Drop tables if they exist
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS user_transactions;

-- Drop index if it exists
DROP INDEX IF EXISTS username;

-- Create tables and index
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username TEXT NOT NULL, 
    hash TEXT NOT NULL,
    cash NUMERIC NOT NULL DEFAULT 10000.00
);

CREATE UNIQUE INDEX username ON users (username);

CREATE TABLE user_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id INTEGER NOT NULL,
    share_name TEXT NOT NULL,
    share_price NUMERIC NOT NULL,
    share_symbol TEXT NOT NULL,
    total_shares INTEGER NOT NULL,
    transaction_type TEXT NOT NULL,
    date_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

