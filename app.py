from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
    UserMixin,
)
from forms import LoginForm
from models import db, Judge, Project, Criteria, Score
from flask_wtf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

csrf = CSRFProtect(app)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to 'login' page if not logged in

@login_manager.user_loader
def load_user(user_id):
    return Judge.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        judge = Judge.query.filter_by(username=username).first()
        if judge and judge.password == password:
            login_user(judge)
            flash('Logged in successfully.')
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            else:
                if judge.is_admin:
                    return redirect(url_for('summary'))
                else:
                    first_project = Project.query.first()
                    if first_project:
                        return redirect(url_for('score', project_id=first_project.id))
                    else:
                        flash('No projects available.')
                        return redirect(url_for('logout'))
        else:
            flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# ... [previous imports and setup] ...

@app.route('/score/<int:project_id>', methods=['GET', 'POST'])
@login_required
def score(project_id):
    if current_user.is_admin:
        flash('Admins cannot score projects.')
        return redirect(url_for('summary'))

    project = Project.query.get_or_404(project_id)
    criteria = Criteria.query.all()
    all_projects = Project.query.all()

    # Retrieve existing scores
    existing_scores = {score.criterion_id: score.score for score in Score.query.filter_by(
        judge_id=current_user.id,
        project_id=project.id
    ).all()}

    if request.method == 'POST':
        if 'submit_scores' in request.form:
            # Handle score submission
            for criterion in criteria:
                field_name = f'score_{criterion.id}'
                score_value = request.form.get(field_name)
                if score_value:
                    existing_score = Score.query.filter_by(
                        judge_id=current_user.id,
                        project_id=project.id,
                        criterion_id=criterion.id
                    ).first()
                    if existing_score:
                        existing_score.score = int(score_value)
                    else:
                        new_score = Score(
                            judge_id=current_user.id,
                            project_id=project.id,
                            criterion_id=criterion.id,
                            score=int(score_value)
                        )
                        db.session.add(new_score)
            db.session.commit()
            flash('Scores submitted successfully.')
            return redirect(url_for('score', project_id=project.id))
        elif 'reset_scores' in request.form:
            # Handle score reset
            Score.query.filter_by(
                judge_id=current_user.id,
                project_id=project.id
            ).delete()
            db.session.commit()
            flash('Scores have been reset.')
            return redirect(url_for('score', project_id=project.id))

    # Retrieve existing scores again after any changes
    existing_scores = {score.criterion_id: score.score for score in Score.query.filter_by(
        judge_id=current_user.id,
        project_id=project.id
    ).all()}

    return render_template('score.html', project=project, criteria=criteria, existing_scores=existing_scores, all_projects=all_projects)

# ... [previous imports and setup] ...

@app.route('/summary')
@login_required
def summary():
    if not current_user.is_admin:
        abort(403)
    
    projects = Project.query.all()
    judges = Judge.query.filter_by(is_admin=False).all()
    
    summary_data = []

    for project in projects:
        project_data = {
            'project_name': project.name,
            'judges_scores': {},
            'total_score': 0
        }
        total_project_score = 0
        for judge in judges:
            judge_scores = Score.query.filter_by(
                project_id=project.id,
                judge_id=judge.id
            ).all()
            if judge_scores:
                judge_total = sum(score.score for score in judge_scores)
                project_data['judges_scores'][judge.username] = judge_total
            else:
                project_data['judges_scores'][judge.username] = 'No score yet'
        # Calculate total score from all judges who have scored
        total_project_score = sum(
            judge_total if isinstance(judge_total, int) else 0
            for judge_total in project_data['judges_scores'].values()
        )
        project_data['total_score'] = total_project_score
        summary_data.append(project_data)
    
    # Sort projects by total score in descending order
    summary_data = sorted(summary_data, key=lambda x: x['total_score'], reverse=True)
    
    return render_template('summary.html', summary_data=summary_data, judges=judges)

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add judges if not already added
        if Judge.query.count() == 0:
            judges = [
                Judge(username='emma', password='password1'),
                Judge(username='john', password='password2'),
                Judge(username='sofia', password='password3'),
                Judge(username='erik', password='password4'),
                Judge(username='johnole', password='password5'),
                Judge(username='silje', password='password6'),
                Judge(username='wan', password='password7'),
                Judge(username='admin', password='adminpassword', is_admin=True),
            ]
            db.session.add_all(judges)
            db.session.commit()
        # Add projects
        if Project.query.count() == 0:
            projects = [
                Project(name='Project Alpha'),
                Project(name='Project Beta'),
                Project(name='Project Gamma'),
            ]
            db.session.add_all(projects)
            db.session.commit()
        # Add criteria
        if Criteria.query.count() == 0:
            criteria_list = [
                Criteria(name='Empower People (40%)'),
                Criteria(name='Strategic Alignment (15%)'),
                Criteria(name='Innovation & Creativity (15%)'),
                Criteria(name='Impact Potential (ROI & Effort) (15%)'),
                Criteria(name='Presentation and Demo Quality (15%)'),
            ]
            db.session.add_all(criteria_list)
            db.session.commit()
    app.run(debug=True)