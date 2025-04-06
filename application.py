from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

application = Flask(__name__)
application.secret_key = 'your_secret_key'


def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT CHECK(role IN ('admin', 'staff')) NOT NULL
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    price REAL NOT NULL
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS bills (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    staff_username TEXT,
                    total REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS bill_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bill_id INTEGER,
                    item_id INTEGER,
                    item_name TEXT,
                    quantity INTEGER,
                    price REAL,
                    subtotal REAL,
                    FOREIGN KEY (bill_id) REFERENCES bills(id)
                )''')

    conn.commit()
    conn.close()

init_db()

@application.route('/')
def home():
    return redirect(url_for('login'))

@application.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                      (username, password, role))
            conn.commit()
            flash("Registered successfully. Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
        finally:
            conn.close()

    return render_template('register.html')

@application.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password_input):
            session['username'] = user[1]
            session['role'] = user[3]
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "danger")

    return render_template('login.html')

@application.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    if session['role'] == 'admin':
        return redirect(url_for('inventory_admin'))
    elif session['role'] == 'staff':
        return redirect(url_for('inventory_staff'))
    else:
        flash("Invalid role!", "danger")
        return redirect(url_for('login'))

@application.route('/admin/inventory')
def inventory_admin():
    if 'username' not in session or session['role'] != 'admin':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM inventory")
    items = c.fetchall()
    conn.close()
    return render_template('inventory_admin.html', items=items)

@application.route('/staff/inventory')
def inventory_staff():
    if 'username' not in session or session['role'] != 'staff':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM inventory")
    items = c.fetchall()
    conn.close()
    return render_template('inventory_staff.html', items=items)

@application.route('/admin/add_item', methods=['POST'])
def add_item():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    name = request.form['name']
    quantity = int(request.form['quantity'])
    price = float(request.form['price'])

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO inventory (name, quantity, price) VALUES (?, ?, ?)",
              (name, quantity, price))
    conn.commit()
    conn.close()

    flash("Item added successfully!", "success")
    return redirect(url_for('inventory_admin'))

@application.route('/admin/update_item/<int:item_id>', methods=['POST'])
def update_item(item_id):
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    name = request.form['name']
    quantity = int(request.form['quantity'])
    price = float(request.form['price'])

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("UPDATE inventory SET name=?, quantity=?, price=? WHERE id=?",
               (name, quantity, price, item_id))
    conn.commit()
    conn.close()

    flash("Item updated successfully!", "info")
    return redirect(url_for('inventory_admin'))

@application.route('/admin/delete_item/<int:item_id>')
def delete_item(item_id):
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM inventory WHERE id=?", (item_id,))
    conn.commit()
    conn.close()

    flash("Item deleted!", "warning")
    return redirect(url_for('inventory_admin'))

@application.route('/staff/new_bill')
def new_bill():
    if 'username' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO bills (staff_username, total) VALUES (?, ?)", (session['username'], 0))
    bill_id = c.lastrowid
    conn.commit()
    conn.close()

    return redirect(url_for('create_bill', bill_id=bill_id))


@application.route('/staff/create_bill')
def create_bill():
    if 'username' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    bill_id = request.args.get('bill_id', type=int)
    if not bill_id:
        flash("No active bill. Please create a new bill.", "warning")
        return redirect(url_for('new_bill'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM inventory")
    inventory = c.fetchall()

    c.execute("SELECT * FROM bills WHERE id = ?", (bill_id,))
    bill = c.fetchone()

    items = []
    total = 0
    if bill:
        c.execute("SELECT * FROM bill_items WHERE bill_id = ?", (bill_id,))
        items = c.fetchall()
        total = sum(item[6] for item in items)

    conn.close()
    return render_template('create_bill.html', inventory=inventory, items=items, total=total, bill_id=bill_id)

@application.route('/staff/add_to_bill', methods=['POST'])
def add_to_bill():
    if 'username' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    bill_id = int(request.form['bill_id'])
    item_id = int(request.form['item_id'])
    quantity = int(request.form['quantity'])

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM inventory WHERE id = ?", (item_id,))
    item = c.fetchone()

    if not item or item[2] < quantity:
        flash("Insufficient stock!", "danger")
        return redirect(url_for('create_bill', bill_id=bill_id))

    subtotal = quantity * item[3]

    # Insert item into bill
    c.execute('''INSERT INTO bill_items (bill_id, item_id, item_name, quantity, price, subtotal)
                 VALUES (?, ?, ?, ?, ?, ?)''', (bill_id, item_id, item[1], quantity, item[3], subtotal))

    # Update inventory
    c.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ?", (quantity, item_id))

    # Update total in bill
    c.execute("UPDATE bills SET total = total + ? WHERE id = ?", (subtotal, bill_id))

    conn.commit()
    conn.close()
    flash("Item added to bill!", "success")
    return redirect(url_for('create_bill', bill_id=bill_id))


@application.route('/staff/remove_from_bill/<int:item_id>/<int:bill_id>')
def remove_from_bill(item_id, bill_id):
    if 'username' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM bill_items WHERE id = ?", (item_id,))
    item = c.fetchone()

    if item:
        # Restore inventory
        c.execute("UPDATE inventory SET quantity = quantity + ? WHERE id = ?", (item[4], item[2]))
        # Subtract subtotal from bill total
        c.execute("UPDATE bills SET total = total - ? WHERE id = ?", (item[6], bill_id))
        # Remove item
        c.execute("DELETE FROM bill_items WHERE id = ?", (item_id,))

    conn.commit()
    conn.close()
    flash("Item removed and inventory restored.", "info")
    return redirect(url_for('create_bill', bill_id=bill_id))

@application.route('/staff/print_bill/<int:bill_id>')
def print_bill(bill_id):
    if 'username' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM bills WHERE id = ?", (bill_id,))
    bill = c.fetchone()

    c.execute("SELECT * FROM bill_items WHERE bill_id = ?", (bill_id,))
    items = c.fetchall()
    conn.close()

    return render_template('print_bill.html', bill=bill, items=items)

@application.route('/staff/old_bills', methods=['GET', 'POST'])
def old_bills():
    if 'username' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    search_query = request.form.get('search') if request.method == 'POST' else ''
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    if search_query:
        c.execute('''
            SELECT * FROM bills 
            WHERE staff_username = ? AND (id LIKE ? OR date LIKE ?) 
            ORDER BY id DESC
        ''', (session['username'], f"%{search_query}%", f"%{search_query}%"))
    else:
        c.execute('''
            SELECT * FROM bills 
            WHERE staff_username = ? 
            ORDER BY id DESC
        ''', (session['username'],))

    bills = c.fetchall()
    conn.close()

    return render_template('old_bills.html', bills=bills, search_query=search_query)


@application.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    application.run(debug=True)
