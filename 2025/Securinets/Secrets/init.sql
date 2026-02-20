
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE,
  password TEXT NOT NULL,
  description TEXT DEFAULT 'Administrator account',
  role TEXT DEFAULT 'user'
);


CREATE TABLE IF NOT EXISTS msgs (
  id SERIAL PRIMARY KEY,
  userId INT NOT NULL REFERENCES users(id),
  msg TEXT NOT NULL,
  type TEXT DEFAULT 'general',
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS flags (
  id SERIAL PRIMARY KEY,
  flag TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS logs (
  id SERIAL PRIMARY KEY,
  userId INT REFERENCES users(id),
  action TEXT NOT NULL,
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


INSERT INTO flags (flag)
VALUES ('Securinets{fake}');



INSERT INTO users (username, password, description, role)
VALUES ('admin', '$2b$10$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', 'This is the admin account', 'admin');


CREATE TABLE IF NOT EXISTS secrets (
  id SERIAL PRIMARY KEY,
  ownerId INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_secrets_ownerId ON secrets(ownerId);