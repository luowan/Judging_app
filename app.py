from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirects to login page if not authenticated
csrf = CSRFProtect(app)

# Models
class Judge(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Judge {self.username}>'

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Project {self.name}>'

class Criteria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    weight = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f'<Criteria {self.name}>'

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    judge_id = db.Column(db.Integer, db.ForeignKey('judge.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    criteria_id = db.Column(db.Integer, db.ForeignKey('criteria.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)

    judge = db.relationship('Judge', backref='scores')
    project = db.relationship('Project', backref='scores')
    criteria = db.relationship('Criteria', backref='scores')

    def __repr__(self):
        return f'<Score Judge:{self.judge_id} Project:{self.project_id} Criteria:{self.criteria_id} Score:{self.score}>'

# User loader
@login_manager.user_loader
def load_user(user_id):
    return Judge.query.get(int(user_id))

# Decorator for admin-required routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if not current_user.is_admin:
            flash('You do not have permission to access this page.', 'error')
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        judge = Judge.query.filter_by(username=username).first()
        if judge and check_password_hash(judge.password, password):
            login_user(judge)
            flash('Logged in successfully!', 'success')
            if judge.is_admin:
                return redirect(url_for('summary'))
            else:
                return redirect(url_for('score'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/score')
@app.route('/score/<int:project_id>', methods=['GET', 'POST'])
@login_required
def score(project_id=None):
    if current_user.is_admin:
        flash('Admins cannot score projects.', 'error')
        return redirect(url_for('summary'))
    
    projects = Project.query.all()
    
    # If no project_id is provided, redirect to the first project
    if project_id is None:
        if projects:
            return redirect(url_for('score', project_id=projects[0].id))
        else:
            flash('No projects available to score.', 'error')
            return redirect(url_for('criteria'))
    
    project = Project.query.get_or_404(project_id)
    criteria = Criteria.query.all()
    existing_scores = {}
    weighted_scores = {}
    total_weighted_score = 0

    # Fetch existing scores and calculate weighted scores
    for criterion in criteria:
        score = Score.query.filter_by(
            judge_id=current_user.id,
            project_id=project.id,
            criteria_id=criterion.id
        ).first()
        if score:
            existing_scores[criterion.id] = score.score
            weighted_score = score.score * criterion.weight
            weighted_scores[criterion.id] = round(weighted_score, 2)
            total_weighted_score += weighted_score
        else:
            existing_scores[criterion.id] = None
            weighted_scores[criterion.id] = None

    total_weighted_score = round(total_weighted_score, 2)

    if request.method == 'POST':
        if 'submit_scores' in request.form:
            for criterion in criteria:
                score_value = request.form.get(f'score_{criterion.id}')
                if score_value:
                    try:
                        score_value = int(score_value)
                        if not (0 <= score_value <= 10):
                            flash(f'Score for {criterion.name} must be between 0 and 10.', 'error')
                            return redirect(url_for('score', project_id=project.id))
                    except ValueError:
                        flash(f'Invalid score for {criterion.name}.', 'error')
                        return redirect(url_for('score', project_id=project.id))
                    
                    score = Score.query.filter_by(
                        judge_id=current_user.id,
                        project_id=project.id,
                        criteria_id=criterion.id
                    ).first()
                    if score:
                        score.score = score_value
                    else:
                        new_score = Score(
                            judge_id=current_user.id,
                            project_id=project.id,
                            criteria_id=criterion.id,
                            score=score_value
                        )
                        db.session.add(new_score)
            db.session.commit()
            flash('Scores submitted successfully.', 'success')
            return redirect(url_for('score', project_id=project.id))
        elif 'reset_scores' in request.form:
            Score.query.filter_by(
                judge_id=current_user.id,
                project_id=project.id
            ).delete()
            db.session.commit()
            flash('Scores reset successfully.', 'success')
            return redirect(url_for('score', project_id=project.id))

    all_projects = projects  # For navigation tabs
    return render_template('score.html', project=project, criteria=criteria,
                           existing_scores=existing_scores, weighted_scores=weighted_scores,
                           total_weighted_score=total_weighted_score, all_projects=all_projects)

@app.route('/summary')
@login_required
@admin_required
def summary():
    projects = Project.query.all()
    judges = Judge.query.filter_by(is_admin=False).all()
    criteria = Criteria.query.all()
    summary_data = []

    for project in projects:
        project_data = {'project_name': project.name, 'judges_scores': {}}
        total_project_score = 0
        for judge in judges:
            total_weighted_score = 0
            judge_scores = Score.query.filter_by(
                project_id=project.id,
                judge_id=judge.id
            ).all()
            if judge_scores:
                for score in judge_scores:
                    criterion = Criteria.query.get(score.criteria_id)
                    weighted_score = score.score * criterion.weight
                    total_weighted_score += weighted_score
                project_data['judges_scores'][judge.username] = round(total_weighted_score, 2)
            else:
                project_data['judges_scores'][judge.username] = 'No score yet'
            
            # Add the judge's total score for this project to the total project score
            total_project_score += total_weighted_score
        
        project_data['total_score'] = round(total_project_score, 2)
        summary_data.append(project_data)

    # Sort projects by total score in descending order
    summary_data = sorted(summary_data, key=lambda x: x['total_score'], reverse=True)

    return render_template('summary.html', summary_data=summary_data, judges=judges)

@app.route('/criteria')
@login_required
def criteria():
    criteria = Criteria.query.all()
    return render_template('criteria.html', criteria=criteria)

# Error handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Context processor to inject current year
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

# Initialize the database and create default entries
def initialize_database():
    db.create_all()

    # Initialize judges
    if Judge.query.count() == 0:
        judges = [
            Judge(username='emma', password=generate_password_hash('password1'), is_admin=False),
            Judge(username='wan', password=generate_password_hash('password2'), is_admin=False),
            Judge(username='john', password=generate_password_hash('password3'), is_admin=False),
            Judge(username='sofia', password=generate_password_hash('password4'), is_admin=False),
            Judge(username='erik', password=generate_password_hash('password5'), is_admin=False),
            Judge(username='johnole', password=generate_password_hash('password6'), is_admin=False),
            Judge(username='silje', password=generate_password_hash('password7'), is_admin=False),
            Judge(username='admin', password=generate_password_hash('adminpassword'), is_admin=True),
            # Add other judges as needed
        ]
        db.session.add_all(judges)
        db.session.commit()

    # Initialize projects
    if Project.query.count() == 0:
        projects = [
            Project(name='DIY'),
            Project(name='IoT'),
            Project(name='GTFO'),
            Project(name='PITA'),
            Project(name='DevOps'),
            Project(name='Mobile'),
            Project(name='BTW'),
            Project(name='ASAP'),
            Project(name='CAFE/DS'),
            Project(name='FAIR'),
            # Add other projects as needed
        ]
        db.session.add_all(projects)
        db.session.commit()

    # Initialize criteria
    if Criteria.query.count() == 0:
        criteria_list = [
            Criteria(name='Empower People', weight=0.4),
            Criteria(name='Strategic Alignment', weight=0.15),
            Criteria(name='Innovation & Creativity', weight=0.15),
            Criteria(name='Impact Potential', weight=0.15),
            Criteria(name='Presentation and Demo Quality', weight=0.15),
        ]
        db.session.add_all(criteria_list)
        db.session.commit()

# Run the application
if __name__ == '__main__':
    with app.app_context():
        initialize_database()
    app.run(debug=True)