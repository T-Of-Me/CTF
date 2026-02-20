import sqlite3
import secrets

ADMIN_PASSWORD = secrets.token_hex(12)
print(f"Admin password: {ADMIN_PASSWORD}")

def get_db_connection():
    conn = sqlite3.connect("store.db")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        money REAL NOT NULL,
        email TEXT DEFAULT 'test@gmail.com',
        phone TEXT DEFAULT '0123456789',
        avatar_url TEXT DEFAULT '/static/avatar.jpg',
        role TEXT DEFAULT 'user' CHECK(role IN ('admin', 'user'))
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        image_url TEXT NOT NULL,
        description TEXT NOT NULL,
        public BOOLEAN DEFAULT TRUE
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        FOREIGN KEY (username) REFERENCES users(username),
        FOREIGN KEY (product_id) REFERENCES products(id)
    )
    """)

    users_data = [
        ("admin", f"{ADMIN_PASSWORD}", 2000.05, "admin@localhost", "0123456789", "/static/avatar.jpg", "admin"),
        ("Bob", secrets.token_hex(12), 100, "bob@gmail.com", "0123456789", "/static/avatar.jpg", "user"),
        ("Charlie", secrets.token_hex(12), 100, "charlie@gmail.com", "0123456789", "/static/avatar.jpg", "user"),
    ]
    cursor.executemany("INSERT OR IGNORE INTO users (username, password, money, email, phone, avatar_url, role) VALUES (?, ?, ?, ?, ?, ?, ?)", users_data)

    products_data = [
        ("Laptop", 1.20, "/static/laptop.jpg", "This is a basic laptop", 1),
        ("Phone", 8.99, "/static/phone.jpg", "This is a basic phone", 1),
        ("Tablet", 30.00, "/static/tablet.jpg", "This is a very basic tablet of HOLACTF", 1),
        ("FLAG", 10000, "/static/flag.jpg", "EHCTF{Leak_the_flag}", 1)
    ]
   
    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("INSERT INTO products (name, price, image_url, description, public) VALUES (?, ?, ?, ?, ?)", products_data)

    conn.commit()
    conn.close()

def add_user(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO users (username, password, money) VALUES (?, ?, ?)",
                   (username, password, 0))
    conn.commit()
    conn.close()

def is_user_exist(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def get_user(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username=?", (username,))
    result=cursor.fetchone()
    conn.close()
    return result

def get_all_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    result = cursor.fetchall()
    conn.close()
    return result

def get_all_product(private = False):
    conn = get_db_connection()
    cursor=conn.cursor()
    if private:
        cursor.execute("SELECT * FROM products")
    else:
        cursor.execute("SELECT * FROM products WHERE public = 1")
    result=cursor.fetchall()
    return result

def get_product(id):
    conn = get_db_connection()
    cursor=conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id=? AND public = 1", (id,))
    result=cursor.fetchone()
    return result

def search_product(string):
    conn = get_db_connection()
    cursor=conn.cursor()
    search_pattern = f"%{string}%"
    cursor.execute("SELECT * FROM products WHERE (name LIKE ? OR description LIKE ?) AND public = 1", (search_pattern, search_pattern))
    result=cursor.fetchall()
    return result

def edit_user(id, email, phone, avatar_url):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET email=?, phone=?, avatar_url=? WHERE id=?", (email, phone, avatar_url, id))
    conn.commit()
    conn.close()

def add_product(name, price, image_url, description):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO products (name, price, image_url, description) VALUES (?, ?, ?, ?)", (name, price, image_url, description))
    conn.commit()
    conn.close()

def edit_product(id, name, price, image_url, description):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE products SET name=?, price=?, image_url=?, description=? WHERE id=?", (name, price, image_url, description, id))
    conn.commit()
    conn.close()

def delete_product(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE id=?", (id,))
    conn.commit()
    conn.close()

def get_order_base_on(input, type):
    conn = get_db_connection()
    cursor = conn.cursor()

    if type == "username":
        cursor.execute("""
            SELECT p.name, o.quantity, p.price, (o.quantity * p.price) AS total_price
            FROM orders o
            JOIN products p ON o.product_id = p.id
            WHERE o.username LIKE ?
        """, (f"%{input}%",))

    elif type == "product":
        cursor.execute("""
            SELECT u.username, o.quantity, p.price, (o.quantity * p.price) AS total_price
            FROM orders o
            JOIN users u ON o.username = u.username
            JOIN products p ON o.product_id = p.id
            WHERE p.name LIKE ?
        """, (f"%{input}%",))

    result = cursor.fetchall()
    conn.close()
    return result


def buying_product(username, product_id, number):
    conn = get_db_connection()
    cursor = conn.cursor()
    try: 
        cursor.execute("SELECT money FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return False
        user_money = user[0]

        cursor.execute("SELECT price FROM products WHERE id=?", (product_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return False
        product_price = row[0]
        
        if user_money >= product_price * number and number > 0:
            new_money = user_money - product_price * number
            cursor.execute("UPDATE users SET money=? WHERE username=?", (new_money, username))
            cursor.execute(f"INSERT INTO orders (username, product_id, quantity) VALUES ((SELECT username FROM users WHERE username='{username}'), ?, ?)", (product_id, number))
            conn.commit()
            conn.close()
            return True
        else:
            conn.close()
            return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.close()
        return False
    
def get_order_history(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.name, o.quantity, p.price, (o.quantity * p.price) AS total_price
        FROM orders o
        JOIN users u ON o.username = u.username
        JOIN products p ON o.product_id = p.id
        WHERE u.id = ?
    """, (id,))
    result = cursor.fetchall()
    conn.close()
    return result

def get_all_orders():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT o.id, o.username, p.name, o.quantity, p.price, (o.quantity * p.price) AS total_price
        FROM orders o
        JOIN users u ON o.username = u.username
        JOIN products p ON o.product_id = p.id
    """)
    result = cursor.fetchall()
    conn.close()
    return result

def add_money(username, money):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET money=money+? WHERE username=?", (money, username))
    conn.commit()
    conn.close()