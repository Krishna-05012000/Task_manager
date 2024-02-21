from flask import Blueprint, render_template, request, redirect, url_for,make_response
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token,set_access_cookies
from app import db, bcrypt
from app.models import User, Task


import logging
from logging.handlers import RotatingFileHandler

logging.basicConfig(level=logging.INFO)  # Adjust as per your need, e.g., DEBUG, ERROR
logger = logging.getLogger(__name__)
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
logger.addHandler(handler)

bp = Blueprint('main', __name__)


@bp.route('/logout')
def logout():
    response = make_response(redirect(url_for('main.login')))
    response.set_cookie('access_token', '', httponly=True, max_age=0)
    return response


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            return "User already exists"
      
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        logger.info(f'New user registered: {username}')
        return redirect(url_for('main.login'))
    return render_template('register.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            logger.info(f'User logged in: {username}')
            access_token = create_access_token(identity=username)
            response = make_response(redirect(url_for('main.home'), 302))
            set_access_cookies(response, access_token)
            return response
        else:
            logger.warning(f'Failed login attempt for: {username}')
            return "Bad username or password"
    return render_template('login.html')



@bp.route('/')
@jwt_required()
def home():
    current_user = get_jwt_identity()
    tasks = Task.query.filter_by(user_id=current_user).all() if current_user else []
    return render_template('home.html', tasks=tasks)

@bp.route('/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user_id = get_jwt_identity()  
    tasks = Task.query.filter_by(user_id=current_user_id).all()
    return render_template('home.html', tasks=tasks)

@bp.route('/task/create', methods=['POST'])
@jwt_required()
def create_task():
    user_id = get_jwt_identity()
    print('create_task',user_id)
    title = request.form['title']
    description = request.form['description']
    task = Task(title=title, description=description, user_id=user_id)
    db.session.add(task)
    db.session.commit()
    logger.info(f'Task created for user {user_id}: {title}')
    return redirect(url_for('main.home'))

@bp.route('/task/update/<int:task_id>', methods=['POST'])
@jwt_required()
def update_task(task_id):
    task = Task.query.get(task_id)
    task.title = request.form['title']
    task.description = request.form['description']
    db.session.commit()
    logger.info(f'Task updated: {task_id}')
    return redirect(url_for('main.home'))

@bp.route('/task/delete/<int:task_id>', methods=['POST'])
@jwt_required()
def delete_task(task_id):
    task = Task.query.get(task_id)
    db.session.delete(task)
    db.session.commit()
    logger.info(f'Task deleted: {task_id}')
    return redirect(url_for('main.home'))
