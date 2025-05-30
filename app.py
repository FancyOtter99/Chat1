from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash
from flask_socketio import SocketIO, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change_this_super_secret_key'  # Seriously, change it or everyone chats as you
socketio = SocketIO(app)

users = {}
groups = {
    'main': {'password': None, 'members': set()}
}
group_memberships = {}  # Tracks which user passed which group's password

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    if username in users:
        return render_template('login.html', error="Username already taken")
    users[username] = generate_password_hash(password)
    flash("Signup successful, please login!")
    return redirect(url_for('login'))

@app.route('/browse')
def browse():
    if 'username' not in session:
        return redirect(url_for('login'))
    error = request.args.get('error')
    return render_template('browse.html', groups=groups, error=error)

@app.route('/create_group', methods=['POST'])
def create_group():
    if 'username' not in session:
        return redirect(url_for('login'))

    group_name = request.form.get('group_name', '').strip()
    password = request.form.get('password') or None

    if not group_name:
        return redirect(url_for('browse', error="Group name cannot be empty"))
    if group_name in groups:
        return redirect(url_for('browse', error="Group already exists"))

    groups[group_name] = {'password': password, 'members': set()}
    return redirect(url_for('browse'))

@app.route('/group/<group_name>', methods=['GET', 'POST'])
def group(group_name):
    if 'username' not in session:
        return redirect(url_for('login'))
    if group_name not in groups:
        return "Group not found", 404

    username = session['username']
    allowed_users = group_memberships.get(group_name, set())

    # Check password access if required and user hasn't passed it yet
    if groups[group_name]['password'] and username not in allowed_users:
        if request.method == 'POST':
            pw = request.form.get('password')
            if pw != groups[group_name]['password']:
                return render_template('password.html', group_name=group_name, error="Wrong password!")
            # Password correct, mark user as allowed
            group_memberships.setdefault(group_name, set()).add(username)
        else:
            return render_template('password.html', group_name=group_name)

    return render_template('group.html', group_name=group_name, username=username)

@app.route('/leave_group/<group_name>', methods=['POST'])
def leave_group(group_name):
    username = session.get('username')
    if not username or group_name not in groups:
        return jsonify({'success': False}), 400

    if group_name in group_memberships:
        group_memberships[group_name].discard(username)
    leave_room(group_name)  # Make sure socket leaves room as well, though this happens on client disconnect normally

    emit('receive_message', {'username': 'System', 'message': f'{username} left the group.'}, room=group_name, namespace='/')
    return jsonify({'success': True})

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    username = session.get('username')
    if username:
        for g in group_memberships:
            group_memberships[g].discard(username)
        session.pop('username')
    return redirect(url_for('login'))

# Socket.IO events

@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    username = session.get('username')
    if not username or not room:
        return

    # Access check except for main
    if room != 'main':
        allowed_users = group_memberships.get(room, set())
        if username not in allowed_users:
            emit('receive_message', {'username': 'System', 'message': 'Access denied.'})
            return

    join_room(room)
    emit('receive_message', {'username': 'System', 'message': f'{username} joined {room}.'}, room=room)

@socketio.on('leave')
def handle_leave(data):
    room = data.get('room')
    username = session.get('username')
    if not username or not room:
        return

    leave_room(room)
    emit('receive_message', {'username': 'System', 'message': f'{username} left {room}.'}, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    room = data.get('room')
    username = session.get('username')
    message = data.get('message')
    if not username or not room or not message:
        return

    emit('receive_message', {'username': username, 'message': message}, room=room)

if __name__ == '__main__':
    socketio.run(app, debug=True)
