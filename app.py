from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
csrf = CSRFProtect(app)

# Models
class Judge(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))

class Criteria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    weight = db.Column(db.Float)

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    judge_id = db.Column(db.Integer, db.ForeignKey('judge.id'))
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    criteria_id = db.Column(db.Integer, db.ForeignKey('criteria.id'))
    score = db.Column(db.Integer)

# User loader
@login_manager.user_loader
def load_user(user_id):
    return Judge.query.get(int(user_id))

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        judge = Judge.query.filter_by(username=username).first()
        if judge and check_password_hash(judge.password, password):
            login_user(judge)
            if judge.is_admin:
                return redirect(url_for('summary'))
            else:
                return redirect(url_for('score'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/score')
@app.route('/score/<int:project_id>', methods=['GET', 'POST'])
@login_required
def score(project_id=None):
    if current_user.is_admin:
        abort(403)
    
    projects = Project.query.all()
    
    # If no project_id is provided, redirect to the first project
    if project_id is None:
        if projects:
            return redirect(url_for('score', project_id=projects[0].id))
        else:
            flash('No projects available to score.')
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
                    score_value = int(score_value)
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
            flash('Scores submitted successfully.')
            return redirect(url_for('score', project_id=project.id))
        elif 'reset_scores' in request.form:
            Score.query.filter_by(
                judge_id=current_user.id,
                project_id=project.id
            ).delete()
            db.session.commit()
            flash('Scores reset successfully.')
            return redirect(url_for('score', project_id=project.id))

    all_projects = projects  # For navigation tabs
    return render_template('score.html', project=project, criteria=criteria,
                           existing_scores=existing_scores, weighted_scores=weighted_scores,
                           total_weighted_score=total_weighted_score, all_projects=all_projects)

@app.route('/summary')
@login_required
def summary():
    if not current_user.is_admin:
        abort(403)
    
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
        # Calculate average total score from all judges who have scored
        total_scores = [
            s for s in project_data['judges_scores'].values()
            if isinstance(s, (int, float))
        ]
        if total_scores:
            average_project_score = sum(total_scores) / len(total_scores)
            project_data['average_score'] = round(average_project_score, 2)
        else:
            project_data['average_score'] = 'No scores yet'
        summary_data.append(project_data)
    
    # Sort projects by average score in descending order
    summary_data = sorted(summary_data, key=lambda x: x['average_score'] if isinstance(x['average_score'], (int, float)) else 0, reverse=True)

    return render_template('summary.html', summary_data=summary_data, judges=judges)

@app.route('/criteria')
@login_required
def criteria():
    return render_template('criteria.html')

# Error handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Context processor to inject current year if needed
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

# Initialize the database and create default entries
if __name__ == '__main__':
    with app.app_context():
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
                Project(name='Project Alpha'),
                Project(name='Project Beta'),
                Project(name='Project Gamma'),
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

    app.run(debug=True)