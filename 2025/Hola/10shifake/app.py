from flask import Flask, url_for, render_template, request, redirect, send_from_directory, flash, make_response
import os
from functools import wraps
from database import *
import jwt
import uuid

app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY", "test")
DATABASE="store.db"
PORT = 5000
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
UPLOAD_FOLDER = os.path.join(app.root_path, "uploads")

init_db()
conn=get_db_connection()

# Setup
app.secret_key = SECRET_KEY
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_user_from_session():
    token = request.cookies.get("token")
    decoded = jwt.decode(token, app.secret_key, algorithms=["HS256"])
    username = decoded.get("username")
    return get_user(username)

def allowed_image_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

def secure_file(filename):
    parts = filename.rsplit(".", 1)  
    name = parts[0]
    extension = parts[1] if len(parts) == 2 else ""
    # No path traversal
    unsecure_characters = "./\\%+&^$#@!`~[]<>|;:,?*"
    for char in unsecure_characters:
        name = name.replace(char, "")
        extension = extension.replace(char, "")
    return f"{name}.{extension}" if extension else name

def upload_image(file):
    if file and allowed_image_file(file.filename):
        filename = f"{uuid.uuid4().hex[0:12]}_{secure_file(file.filename)}"
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        return filename
    return None

def delete_product_image(id):
    product = get_product(id)
    if product and product[3]: 
        image_path = os.path.join(UPLOAD_FOLDER, secure_file(product[3].split("/")[-1]))
        if os.path.exists(image_path):
            os.remove(image_path)

def delete_avatar_image(username):
    user = get_user(username)
    if user and user[6]: 
        image_path = os.path.join(UPLOAD_FOLDER, secure_file(user[6].split("/")[-1]))
        if os.path.exists(image_path):
            os.remove(image_path)

def auth_check(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            token = request.cookies.get("token")
            result_decode = jwt.decode(token, key=app.secret_key, algorithms=["HS256"])
            if is_user_exist(result_decode.get("username")):
                return f(*args, **kwargs)  
            else:
                flash("Please login", "error")
                return redirect("/")
        except Exception:
            flash("Something when wrong", "error")
            return redirect("/")
    return wrapper

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = get_user(username)
        if user:
            stored_password = user[2]  
            if password == stored_password:
                token = jwt.encode({"username": username}, app.secret_key, algorithm="HS256")
                resp = make_response(redirect("/dashboard"))
                resp.set_cookie("token", token, httponly=False, samesite="Lax")
                return resp
            return render_template("login.html", message="Invalid password")
        else:
            return render_template("login.html", message="User not found")
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username=?", (username,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            add_user(username, password)
            token = jwt.encode({"username": username}, app.secret_key, algorithm="HS256")
            resp = make_response(redirect("/dashboard"))
            resp.set_cookie("token", token, httponly=False, samesite="Lax")
            return resp
        else:
            return render_template("login.html", message="User is existed")

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    filename = secure_file(filename)
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/logout')
@auth_check
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("token") 
    return resp

@app.route("/dashboard")
@auth_check
def dashboard():
    result=get_all_product()
    return render_template("dashboard.html", result=result, user = get_user_from_session())

@app.route("/product/<id>")
@auth_check
def product_detail(id):
    result=get_product(id)
    return render_template("product_detail.html", result=result, user=get_user_from_session())

@app.route("/search")
@auth_check
def search():
    query=request.args.get("query", "")
    result=search_product(query)
    return render_template("search.html", result=result, query=query, user=get_user_from_session())

@app.route("/profile")
@auth_check
def profile():
    return render_template("profile.html", user=get_user_from_session())

@app.route("/edit_profile", methods=["GET", "POST"])
@auth_check
def edit_profile():
    user = get_user_from_session()
    if request.method == "POST":
        email = request.form.get("email")
        phone = request.form.get("phone")
        avatar_file = request.files.get("avatar")
        if avatar_file and avatar_file.filename:  
            image_filename = upload_image(avatar_file)
            if not image_filename:
                return render_template("edit_profile.html", user=get_user_from_session(), message="Invalid image file")
            avatar_url = "/uploads/" + image_filename
            delete_avatar_image(user[1])  
        else:
            avatar_url = user[6]
        edit_user(user[0], email, phone, avatar_url)
        return render_template("edit_profile.html", user=get_user_from_session(), message="Profile updated successfully")
    return render_template("edit_profile.html", user=user)

@app.route("/buy_product", methods=["GET", "POST"])
@auth_check
def buy_product():
    if request.method == "POST":
        try:
            username = get_user_from_session()[1]
            product_id = request.form.get("product_id")
            number = int(request.form.get("number", 1))
            is_sucess = buying_product(username, product_id, number)
            if is_sucess:
                return render_template("product_detail.html", result=get_product(product_id), message="Sucessfully bought product", user=get_user_from_session())
            else:
                return render_template("product_detail.html", result=get_product(product_id), message="Not enough money or product not found", user=get_user_from_session())
        except Exception:
             return render_template("product_detail.html", result=get_product(product_id), message="Something when wrong", user=get_user_from_session())
    return render_template("product_detail.html", result=get_product(product_id), user=get_user_from_session())

@app.route("/order_history", methods=["GET"])
@auth_check
def order_history():
    user = get_user_from_session()
    orders = get_order_history(user[0])
    return render_template("order_history.html", orders=orders, user=user)
    
# Admin from here
def is_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            token = request.cookies.get("token")
            result_decode = jwt.decode(token, key=app.secret_key, algorithms=["HS256"])
            if is_user_exist(result_decode.get("username")) and get_user_from_session()[7] == "admin":
                return f(*args, **kwargs)  
            else:
                flash("You are not authorized to access this page", "error")
                return redirect("/")
        except Exception:
            flash(f"Something went wrong", "error")
            return redirect("/")
    return wrapper

@app.route("/admin")
@is_admin
def admin_dashboard():
    users = get_all_users()
    return render_template("admin/admin_dashboard.html", users=users, user=get_user_from_session())

@app.route("/admin/profile/<username>")
@is_admin
def admin_profile(username):
    user = get_user(username)
    if not user:
        return render_template("admin/admin_profile.html", user=None)
    return render_template("admin/admin_profile.html", user=user)

@app.route("/admin/products")
@is_admin
def admin_products():
    products = get_all_product(private=True)
    return render_template("admin/admin_products.html", products=products, user=get_user_from_session())

@app.route("/admin/add_product", methods=["GET", "POST"])
@is_admin
def add_product_route():
    if request.method == "POST":
        name = request.form.get("name", "test product").strip()

        # Validate price input
        price_str = request.form.get("price", "0.00").strip()
        if not price_str.replace(".", "", 1).isdigit():
            return render_template("admin/add_product.html", user=get_user_from_session(), message="Invalid price")
        elif float(price_str) <= 0:
            return render_template("admin/add_product.html", user=get_user_from_session(), message="Price must be greater than 0")

        price = float(price_str)

        # Handle image upload
        image_filename = upload_image(request.files.get("uploaded_image"))
        if image_filename:
            image_url = "/uploads/"+image_filename
        else:
            return render_template("admin/add_product.html", user=get_user_from_session(), message="Invalid image file")

        description = request.form.get("description")
        add_product(name, price, image_url, description)
        return redirect("/admin/products")
    return render_template("admin/add_product.html", user=get_user_from_session())

@app.route("/admin/edit_product/<int:id>", methods=["GET", "POST"])
@is_admin
def edit_product_route(id):
    product = get_product(id)
    if request.method == "POST":
        name = request.form.get("name", product[1]).strip()
        # Validate price input
        price_str = request.form.get("price", str(product[2])).strip()
        if not price_str.replace(".", "", 1).isdigit():
            return render_template("admin/edit_product.html", product=product, user=get_user_from_session(), message="Invalid price")
        elif float(price_str) <= 0:
            return render_template("admin/edit_product.html", product=product, user=get_user_from_session(), message="Price must be greater than 0")
        price = float(price_str)
        # Handle image upload
        file = request.files.get("uploaded_image")
        if file and file.filename:  
            image_filename = upload_image(file)
            if not image_filename:
                return render_template("admin/edit_product.html", product=product, user=get_user_from_session(), message="Invalid image file")
            image_url = "/uploads/" + image_filename
            delete_product_image(id)
        else:
            image_url = product[3]

        description = request.form.get("description", product[4])
        edit_product(id, name, price, image_url, description)
        return redirect("/admin/products")
    return render_template("admin/edit_product.html", product=product, user=get_user_from_session())

@app.route("/admin/delete_product/<int:id>")
@is_admin
def delete_product_route(id):
    product = get_product(id)
    if not product:
        flash("Product not found", "error")
        return redirect("/admin/products")
    delete_product_image(id)
    delete_product(id)
    flash("Product deleted successfully", "success")

    return redirect("/admin/products")

@app.route("/admin/order_history", methods=["GET"])
@is_admin
def admin_order_history():
    user = get_user_from_session()
    orders = get_all_orders()
    return render_template("admin/admin_order_history.html", orders=orders, user=user)

@app.route("/admin/search_order_history", methods=["GET"])
@is_admin
def admin_search_order_history():
    category = request.args.get("category", "")
    search_text = request.args.get("search_text", "")
    current_user = get_user_from_session()
    if category not in ("username", "product"):
        return render_template("admin/admin_search_order.html",message="Category must be username or product", user=current_user)
    orders = get_order_base_on(search_text, category)
    return render_template("admin/admin_search_order.html", orders=orders, user=current_user, category = category, search_text = search_text)

@app.route("/admin/tester", methods=["GET", "POST"])
@is_admin
def admin_logs():
    action = request.args.get("action")
    if action == "healthcheck":
        return "OK", 200
    elif action == "env":
        return str(os.environ), 200
    elif action == "add_money":
        username = request.form.get("username")
        amount = int(request.form.get("amount"))
        try: 
            if is_user_exist(username) and amount>0: 
                add_money(username, amount)
                return "Add money successfull", 200
            else:
                return "User not exist or amount <= 0", 400
        except Exception:
            return "Error ocococ", 404
    else:
        return "What should tenshi do now", 400

# bot uhhh
@app.route("/report")
def report():
    url = request.args.get('url')
    # bot will be complete in the future
    return {"visited": url}, 200 


if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0" , port=PORT)