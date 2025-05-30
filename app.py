from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash
from flask_socketio import SocketIO, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
import os
import redis
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change_this_super_secret_key'
socketio = SocketIO(app)

# Redis connection
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
print(r.ping())  # Should print True if connection is successful
redis_client = redis.from_url(redis_url, decode_responses=True)

# Helper functions to convert sets and dicts to JSON strings for Redis

def redis_get_json(key, default=None):
    val = redis_client.get(key)
    if val is None:
        return default
    return json.loads(val)

def redis_set_json(key, value):
    redis_client.set(key, json.dumps(value))

def redis_set_add(key, member):
    # Store sets as Redis sets for better performance
    redis_client.sadd(key, member)

def redis_set_remove(key, member):
    redis_client.srem(key, member)

def redis_set_members(key):
    return redis_client.smembers(key) or set()

# USERS: store dict {username: password_hash} as Redis hash
# GROUPS: store group info as Redis hash: keys like group:<group_name>:password and group:<group_name>:members (set)
# GROUP_MEMBERSHIPS: store which users passed password per group: key group:<group_name>:allowed_users (set)

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
        password_hash = redis_client.hget('users', username)
        if password_hash and check_password_hash(password_hash, password):
            session['username'] = username
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    if redis_client.hexists('users', username):
        return render_template('login.html', error="Username already taken")
    redis_client.hset('users', username, generate_password_hash(password))
    flash("Signup successful, please login!")
    return redirect(url_for('login'))

@app.route('/browse')
def browse():
    if 'username' not in session:
        return redirect(url_for('login'))
    error = request.args.get('error')

    # Load groups from Redis
    group_names = redis_client.smembers('groups') or set()
    groups = {}
    for group_name in group_names:
        pw = redis_client.get(f'group:{group_name}:password')
        members = redis_client.smembers(f'group:{group_name}:members') or set()
        groups[group_name] = {'password': pw, 'members': members}

    return render_template('browse.html', groups=groups, error=error)

@app.route('/create_group', methods=['POST'])
def create_group():
    if 'username' not in session:
        return redirect(url_for('login'))

    group_name = request.form.get('group_name', '').strip()
    password = request.form.get('password') or None

    if not group_name:
        return redirect(url_for('browse', error="Group name cannot be empty"))
    if redis_client.sismember('groups', group_name):
        return redirect(url_for('browse', error="Group already exists"))

    redis_client.sadd('groups', group_name)
    if password:
        redis_client.set(f'group:{group_name}:password', password)
    else:
        redis_client.delete(f'group:{group_name}:password')
    redis_client.delete(f'group:{group_name}:members')  # new empty set

    return redirect(url_for('browse'))

@app.route('/group/<group_name>', methods=['GET', 'POST'])
def group(group_name):
    if 'username' not in session:
        return redirect(url_for('login'))
    if not redis_client.sismember('groups', group_name):
        return "Group not found", 404

    username = session['username']

    group_password = redis_client.get(f'group:{group_name}:password')
    allowed_users = redis_client.smembers(f'group:{group_name}:allowed_users') or set()

    if group_password and username not in allowed_users:
        if request.method == 'POST':
            pw = request.form.get('password')
            if pw != group_password:
                return render_template('password.html', group_name=group_name, error="Wrong password!")
            redis_client.sadd(f'group:{group_name}:allowed_users', username)
        else:
            return render_template('password.html', group_name=group_name)

    return render_template('group.html', group_name=group_name, username=username)

@app.route('/leave_group/<group_name>', methods=['POST'])
def leave_group(group_name):
    username = session.get('username')
    if not username or not redis_client.sismember('groups', group_name):
        return jsonify({'success': False}), 400

    redis_client.srem(f'group:{group_name}:allowed_users', username)
    redis_client.srem(f'group:{group_name}:members', username)

    leave_room(group_name)  # socket leave room on server side

    emit('receive_message', {'username': 'System', 'message': f'{username} left the group.'}, room=group_name, namespace='/')
    return jsonify({'success': True})

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    username = session.get('username')
    if username:
        group_names = redis_client.smembers('groups') or set()
        for g in group_names:
            redis_client.srem(f'group:{g}:allowed_users', username)
            redis_client.srem(f'group:{g}:members', username)
        session.pop('username')
    return redirect(url_for('login'))

# Socket.IO events

@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    username = session.get('username')
    if not username or not room:
        return

    if room != 'main':
        allowed_users = redis_client.smembers(f'group:{room}:allowed_users') or set()
        if username not in allowed_users:
            emit('receive_message', {'username': 'System', 'message': 'Access denied.'})
            return

    join_room(room)
    redis_client.sadd(f'group:{room}:members', username)
    emit('receive_message', {'username': 'System', 'message': f'{username} joined {room}.'}, room=room)

@socketio.on('leave')
def handle_leave(data):
    room = data.get('room')
    username = session.get('username')
    if not username or not room:
        return

    leave_room(room)
    redis_client.srem(f'group:{room}:members', username)
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
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)


