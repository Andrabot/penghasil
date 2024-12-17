from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'


def init_db():
    with sqlite3.connect('game_lomba_lari.db') as conn:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            coins INTEGER DEFAULT 100)''')
        
        # Create admin table
        cursor.execute('''CREATE TABLE IF NOT EXISTS admin (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL)''')
        
        # Create withdraw_history table
        cursor.execute('''CREATE TABLE IF NOT EXISTS withdraw_history (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            username TEXT NOT NULL,
                            coin_amount INTEGER NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # Add default admin
        cursor.execute('SELECT * FROM admin WHERE username = ?', ('admin',))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO admin (username, password) VALUES (?, ?)',
                           ('admin', generate_password_hash('admin123')))
        
        # Add test user (for testing)
        cursor.execute('SELECT * FROM users WHERE username = ?', ('test_user',))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO users (username, password, coins) VALUES (?, ?, ?)',
                           ('test_user', generate_password_hash('password123'), 100))
        
        conn.commit()



# Routes for users
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect('game_lomba_lari.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                return redirect(url_for('dashboard'))
            else:
                flash('Username atau password salah.', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        with sqlite3.connect('game_lomba_lari.db') as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                conn.commit()
                flash('Registrasi berhasil. Silakan login.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username sudah digunakan.', 'error')

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('game_lomba_lari.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT coins FROM users WHERE id = ?', (session['user_id'],))
        coins = cursor.fetchone()[0]

    return render_template('dashboard.html', username=session['username'], coins=coins)


@app.route('/update_coins', methods=['POST'])
def update_coins():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'User not logged in'}), 403

    try:
        data = request.get_json()
        new_coins = data.get('coins')

        with sqlite3.connect('game_lomba_lari.db') as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET coins = ? WHERE id = ?', (new_coins, session['user_id']))
            conn.commit()

        return jsonify({'status': 'success', 'coins': new_coins})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# Routes for admin
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect('game_lomba_lari.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM admin WHERE username = ?', (username,))
            admin = cursor.fetchone()
            if admin and check_password_hash(admin[2], password):
                session['admin_logged_in'] = True
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Username atau password admin salah.', 'error')

    return render_template('admin_login.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    with sqlite3.connect('game_lomba_lari.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, coins FROM users')
        players = cursor.fetchall()

    return render_template('admin_dashboard.html', players=players)


@app.route('/admin/requests', methods=['GET'])
def admin_requests():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    with sqlite3.connect('game_lomba_lari.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM requests WHERE status = "pending"')
        requests = cursor.fetchall()

    return render_template('admin_requests.html', requests=requests)


@app.route('/admin/approve_request', methods=['POST'])
def approve_request():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    request_id = request.form['request_id']
    with sqlite3.connect('game_lomba_lari.db') as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE requests SET status = "approved" WHERE id = ?', (request_id,))
        conn.commit()

    flash(f'Request ID {request_id} berhasil disetujui.', 'success')
    return redirect(url_for('admin_requests'))


@app.route('/admin/add_coins', methods=['POST'])
def add_coins():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    try:
        player_id = request.form['player_id']
        coins = int(request.form['coins'])

        with sqlite3.connect('game_lomba_lari.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT coins FROM users WHERE id = ?', (player_id,))
            result = cursor.fetchone()
            if not result:
                flash('Player ID tidak ditemukan.', 'error')
                return redirect(url_for('admin_dashboard'))
            
            current_coins = result[0]
            new_coins = current_coins + coins

            # Update coins in the database
            cursor.execute('UPDATE users SET coins = ? WHERE id = ?', (new_coins, player_id))
            conn.commit()

        flash(f'Successfully added {coins} coins to Player ID {player_id}.', 'success')
    except Exception as e:
        flash(f'Error: {e}', 'error')

    return redirect(url_for('admin_dashboard'))


@app.route('/send_to_admin', methods=['POST'])
def send_to_admin():
    try:
        data = request.json
        account_name = data.get('account_name')
        coin_amount = data.get('coin_amount')

        if not account_name or not coin_amount:
            return jsonify({'status': 'error', 'message': 'Data tidak lengkap'}), 400

        with sqlite3.connect('game_lomba_lari.db') as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO requests (account_name, coin_amount) VALUES (?, ?)', (account_name, coin_amount))
            conn.commit()

        return jsonify({'status': 'success', 'message': 'Data berhasil dikirim ke admin'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/game', methods=['GET', 'POST'])
def game():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('game_lomba_lari.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT coins FROM users WHERE id = ?', (session['user_id'],))
        coins = cursor.fetchone()[0]
        username = session['username']

    return render_template('game.html', username=username, coins=coins)

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    allowed_values = [5000, 10000, 20000, 50000]  # Daftar nilai yang diperbolehkan

    with sqlite3.connect('game_lomba_lari.db') as conn:
        cursor = conn.cursor()

        # Ambil saldo koin pengguna
        cursor.execute('SELECT coins FROM users WHERE id = ?', (session['user_id'],))
        user_data = cursor.fetchone()
        if user_data is None:
            flash('Pengguna tidak ditemukan.', 'error')
            return redirect(url_for('login'))

        total_coins = user_data[0]  # Ambil total koin

        if request.method == 'POST':
            try:
                coin_amount = int(request.form['coin_amount'])
            except ValueError:
                flash('Jumlah koin tidak valid.', 'error')
                return redirect(url_for('withdraw'))

            # Validasi nilai koin
            if coin_amount not in allowed_values:
                flash('Jumlah koin tidak valid.', 'error')
            elif coin_amount > total_coins:
                flash('Saldo koin Anda tidak cukup.', 'error')
            else:
                # Kurangi saldo koin pengguna
                cursor.execute('UPDATE users SET coins = coins - ? WHERE id = ?', (coin_amount, session['user_id']))

                # Catat transaksi withdraw
                cursor.execute('INSERT INTO withdraw_history (user_id, username, coin_amount) VALUES (?, ?, ?)',
                               (session['user_id'], session['username'], coin_amount))
                conn.commit()

                # Redirect ke halaman GET setelah transaksi berhasil
                flash('Withdraw berhasil diproses.', 'success')
                return redirect(url_for('withdraw'))  # PRG: Redirect setelah POST

        # Ambil riwayat withdraw pengguna
        cursor.execute('SELECT coin_amount, created_at FROM withdraw_history WHERE user_id = ? ORDER BY created_at DESC',
                       (session['user_id'],))
        withdraw_history = cursor.fetchall()

    # Kirim data ke template
    return render_template(
        'withdraw.html',
        username=session['username'],
        total_coins=total_coins,
        withdraw_history=withdraw_history
    )


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
