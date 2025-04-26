from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re  # Import the regular expression module
from functools import wraps  # Import wraps for decorator

app = Flask(__name__, template_folder='../frontend/templates',
            static_folder='../frontend/static')
app.config['SECRET_KEY'] = 'cema_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cema_cancer_system.db'  # Changed to SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Suppress warning
db = SQLAlchemy(app)

# Configure upload folder
UPLOAD_FOLDER = 'static/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# --- Database Models ---
class Doctor(db.Model):
    __tablename__ = 'doctors'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True,
                            nullable=False)  # This is the doctor's name
    full_name = db.Column(db.String(120), nullable=False)  # Add full name
    work_number = db.Column(db.String(20), unique=True,
                            nullable=False)  # Add work number
    password_hash = db.Column(db.String(128), nullable=False)
    cancer_programs = db.relationship('CancerProgram', backref='doctor',
                                        lazy=True)
    clients = db.relationship('Client', backref='doctor', lazy=True)

    def __init__(self, username, full_name, work_number,
                 password):  # Modified __init__
        self.username = username
        self.full_name = full_name
        self.work_number = work_number
        self.password_hash = generate_password_hash(password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<Doctor {self.username}>'

class Client(db.Model):
    __tablename__ = 'clients'  # Added tablename
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    health_record = db.Column(db.Text)
    programs = db.relationship('ClientProgramEnrollment', backref='client',
                                lazy=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'),
                            nullable=False)  # Changed to doctors.id

    def __repr__(self):
        return f'<Client {self.name}>'

class CancerProgram(db.Model):
    __tablename__ = 'cancer_programs'  # Added tablename
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    stages = db.Column(db.Text, nullable=False)
    duration = db.Column(db.String(50))
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'),
                            nullable=False)  # Changed to doctors.id
    enrollments = db.relationship('ClientProgramEnrollment', backref='program',
                                    lazy=True)

    def __repr__(self):
        return f'<CancerProgram {self.name}>'

class ClientProgramEnrollment(db.Model):
    __tablename__ = 'client_program_enrollments'  # Added tablename
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('clients.id'),
                            nullable=False)  # Changed to clients.id
    program_id = db.Column(db.Integer, db.ForeignKey('cancer_programs.id'),
                            nullable=False)  # Changed to cancer_programs.id
    enrollment_date = db.Column(db.DateTime, default=datetime.utcnow)
    progress_status = db.Column(db.String(100), default="Not Started")
    consistency_track = db.Column(db.Text)

    def __repr__(self):
        return f'<ClientProgramEnrollment {self.id}>'

# --- Database Creation ---
with app.app_context():
    db.create_all()

# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[
        1].lower() in ALLOWED_EXTENSIONS

def get_logged_in_doctor():
    doctor_id = session.get('doctor_id')
    if doctor_id is not None:
        return Doctor.query.get(doctor_id)
    return None

def get_logged_in_client():
    client_id = session.get('client_id')
    if client_id is not None:
        return Client.query.get(client_id)
    return None

def validate_password(password):
    """
    Validates the password against the following criteria:
    - Minimum length of 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*]", password):
        return False, "Password must contain at least one special character (!@#$%^&*)."
    return True, None

def authenticate_user(username, password):
    """
    Authenticates a user and returns the user object if successful, None otherwise.
    """
    doctor = Doctor.query.filter_by(username=username).first()
    if doctor and doctor.check_password(password):
        return doctor
    return None

def authorize_user(user, required_role):
    """
    Checks if the user has the required role.  Returns True if authorized,
    False otherwise.
    """
    # In this application, we only have doctors, so role is always 'doctor'
    return True  # Simplified authorization
    # return user.role == required_role # Removed user.role

# --- Authentication Decorator ---
def login_required(func):
    @wraps(func)  # Preserve original function's metadata
    def wrapper(*args, **kwargs):
        if not session.get('doctor_id'):
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

# --- API Endpoints ---
@app.route('/api/login', methods=['POST'])
def api_login():
    """
    Endpoint for user login.  Returns a JSON response with doctor data.
    """
    if not request.json or not 'username' in request.json or not 'password' in request.json:
        abort(400)  # Bad request

    username = request.json['username']
    password = request.json['password']
    doctor = authenticate_user(username, password)

    if not doctor:
        abort(401)  # Unauthorized

    # In a real application, you would generate a JWT (JSON Web Token) here
    # and return that token to the client.  For simplicity, we're returning
    #  doctor data.
    session['doctor_id'] = doctor.id  # store in session
    return jsonify({
        'id': doctor.id,
        'username': doctor.username,
        'full_name': doctor.full_name,
        'work_number': doctor.work_number
    }), 200

@app.route('/api/patients', methods=['POST'])
@login_required  # Protect the route
def api_create_patient():
    """
    Endpoint to create a new patient.  Requires a doctor login.
    """
    if not request.json or not 'name' in request.json or not 'age' in request.json:
        abort(400)

    doctor_id = session.get('doctor_id')
    doctor = Doctor.query.get(doctor_id)

    name = request.json['name']
    age = request.json['age']
    health_record = request.json.get('health_record', None)

    new_patient = Client(name=name, age=age, health_record=health_record,
                            doctor_id=doctor_id)
    db.session.add(new_patient)
    db.session.commit()

    return jsonify({'id': new_patient.id}), 201  # 201 Created

@app.route('/api/patients/<int:patient_id>', methods=['GET'])
@login_required
def api_get_patient(patient_id):
    """
    Endpoint to retrieve a specific patient.  Requires doctor login.
    """
    doctor_id = session.get('doctor_id')
    doctor = Doctor.query.get(doctor_id)

    patient = Client.query.get_or_404(patient_id)  # Returns 404 if not found

    # Check if the doctor has access to this patient.
    if patient.doctor_id != doctor_id:
        abort(403)  # Forbidden

    patient_data = {
        'id': patient.id,
        'name': patient.name,
        'age': patient.age,
        'health_record': patient.health_record,
    }
    return jsonify(patient_data), 200

@app.route('/api/patients/<int:patient_id>', methods=['PUT'])
@login_required
def api_update_patient(patient_id):
    """Endpoint to update patient data"""
    doctor_id = session.get('doctor_id')
    doctor = Doctor.query.get(doctor_id)

    patient = Client.query.get_or_404(patient_id)
    if patient.doctor_id != doctor_id:
        abort(403)

    if not request.json:
        abort(400)

    # update fields
    patient.name = request.json.get('name', patient.name)
    patient.age = request.json.get('age', patient.age)
    patient.health_record = request.json.get('health_record',
                                            patient.health_record)

    db.session.commit()
    return jsonify({'message': 'Patient updated successfully'}), 200

@app.route('/api/patients/<int:patient_id>/share', methods=['POST'])
@login_required
def api_share_patient(patient_id):
    """Endpoint to share a patient with another doctor."""
    doctor_id = session.get('doctor_id')
    doctor = Doctor.query.get(doctor_id)

    patient = Client.query.get_or_404(patient_id)
    if patient.doctor_id != doctor_id:
        abort(403)  # Doctor doesn't have access

    if not request.json or 'doctor_username' not in request.json:
        abort(400)

    other_doctor = Doctor.query.filter_by(
        username=request.json['doctor_username']).first()
    if not other_doctor:
        abort(404)  # Doctor not found

    # No need to check role, we only have doctors.

    if patient in other_doctor.clients:
        return jsonify(
            {'message': 'Patient already shared with this doctor'}), 200

    other_doctor.clients.append(patient)
    db.session.commit()
    return jsonify({'message': 'Patient shared successfully'}), 200

@app.route('/api/doctors/<int:doctor_id>/patients', methods=['GET'])
@login_required
def api_get_doctor_patients(doctor_id):
    """
    Retrieves all patients for a specific doctor.
    """
    doctor = Doctor.query.get_or_404(doctor_id)

    current_doctor_id = session.get('doctor_id')
    if current_doctor_id != doctor_id:
        abort(403)  # Only the same doctor can access his patients.

    patients_list = []
    for patient in doctor.clients:
        patients_list.append({
            'id': patient.id,
            'name': patient.name,
            'age': patient.age,
            'health_record': patient.health_record
        })
    return jsonify(patients_list), 200

@app.route('/api/clients/<int:client_id>', methods=['GET'])
@login_required
def api_get_client_profile(client_id):
    """
    Endpoint to retrieve a client's profile.  Requires doctor login.
    """
    doctor_id = session.get('doctor_id')
    doctor = Doctor.query.get(doctor_id)

    client = Client.query.get_or_404(client_id)

    # Check if the doctor has access to this client
    if client.doctor_id != doctor_id:
        abort(403)  # Forbidden

    client_data = {
        'id': client.id,
        'name': client.name,
        'age': client.age,
        'health_record': client.health_record,
    }
    return jsonify(client_data), 200
# --- Web Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        doctor_name = request.form['doctor_name']  # Changed from 'username'
        password = request.form['password']
        work_number = request.form.get('work_number')  # Get work number

        doctor = Doctor.query.filter_by(
            username=doctor_name).first()  # Changed to doctor_name

        if doctor:
            # Doctor exists, check password
            if doctor.check_password(password):
                session['doctor_id'] = doctor.id
                return redirect(url_for('doctor_dashboard'))
            else:
                return render_template('login.html', error='Invalid password')
        else:
            # Doctor does not exist, this is first-time registration
            if work_number:  # Make sure work_number was provided
                is_valid, message = validate_password(
                    password)  # Validate password
                if not is_valid:
                    return render_template('login.html', error=message)
                new_doctor = Doctor(username=doctor_name,
                                    full_name=doctor_name,
                                    work_number=work_number,
                                    password=password)  # Use provided data
                db.session.add(new_doctor)
                db.session.commit()
                session['doctor_id'] = new_doctor.id
                return redirect(url_for('doctor_dashboard'))
            else:
                return render_template('login.html',
                                        error='Doctor name not found and Work Number not provided.')
    return render_template('login.html')

@app.route('/doctor_dashboard')
@login_required
def doctor_dashboard():
    doctor_id = session.get('doctor_id')
    doctor = Doctor.query.get(doctor_id)
    cancer_programs = CancerProgram.query.filter_by(
        doctor_id=doctor_id).all()
    clients = Client.query.filter_by(doctor_id=doctor_id).all()
    return render_template('doctor_dashboard.html', doctor=doctor,
                            cancer_programs=cancer_programs, clients=clients)

@app.route('/create_cancer_program', methods=['GET', 'POST'])
@login_required
def create_cancer_program():
    doctor_id = session.get('doctor_id')
    if request.method == 'POST':
        name = request.form['name']
        stages = request.form['stages']
        duration = request.form['duration']
        new_program = CancerProgram(name=name, stages=stages,
                                    duration=duration, doctor_id=doctor_id)
        db.session.add(new_program)
        db.session.commit()
        return redirect(url_for('doctor_dashboard'))
    return render_template('create_cancer_program.html')

@app.route('/register_client', methods=['GET', 'POST'])
@login_required
def register_client():
    doctor_id = session.get('doctor_id')
    if request.method == 'POST':
        name = request.form['name']
        age = request.form['age']
        health_record = request.form['health_record']
        new_client = Client(name=name, age=age, health_record=health_record,
                            doctor_id=doctor_id)
        db.session.add(new_client)
        db.session.commit()
        return redirect(url_for('doctor_dashboard'))
    return render_template('register_client.html')

@app.route('/enroll_client/<int:client_id>', methods=['GET', 'POST'])
@login_required
def enroll_client(client_id):
    doctor_id = session.get('doctor_id')
    client = Client.query.get_or_404(client_id)
    if client.doctor_id != doctor_id:
        return redirect(url_for('login'))
    cancer_programs = CancerProgram.query.filter_by(
        doctor_id=doctor_id).all()
    if request.method == 'POST':
        program_ids = request.form.getlist('programs')
        for program_id in program_ids:
            program = CancerProgram.query.get(program_id)
            if program:
                enrollment = ClientProgramEnrollment(client_id=client.id,
                                                    program_id=program.id)
                db.session.add(enrollment)
        db.session.commit()
        return redirect(url_for('view_client_profile', client_id=client.id))
    return render_template('enroll_client.html', client=client,
                            cancer_programs=cancer_programs)

@app.route('/view_client_profile/<int:client_id>')
@login_required
def view_client_profile(client_id):
    doctor_id = session.get('doctor_id')
    client = Client.query.get_or_404(client_id)
    if client.doctor_id != doctor_id:
        return redirect(url_for('login'))
    enrollments = ClientProgramEnrollment.query.filter_by(
        client_id=client.id).all()
    return render_template('view_client_profile.html', client=client,
                            enrollments=enrollments)

@app.route('/update_enrollment_status/<int:enrollment_id>',
            methods=['POST'])
@login_required
def update_enrollment_status(enrollment_id):
    doctor_id = session.get('doctor_id')
    enrollment = ClientProgramEnrollment.query.get_or_404(enrollment_id)
    client = enrollment.client
    if client.doctor_id != doctor_id:
        return redirect(url_for('login'))
    progress_status = request.form.get('progress_status')
    consistency_track = request.form.get('consistency_track')
    enrollment.progress_status = progress_status
    enrollment.consistency_track = consistency_track
    db.session.commit()
    return redirect(url_for('view_client_profile', client_id=client.id))

@app.route('/search_client', methods=['POST'])
@login_required
def search_client():
    doctor_id = session.get('doctor_id')
    search_term = request.form.get('search_term')
    results = Client.query.filter(
        Client.doctor_id == doctor_id,
        db.or_(Client.name.ilike(f'%{search_term}%'),
               Client.id == search_term)).all()
    doctor = Doctor.query.get(doctor_id)
    return render_template('doctor_dashboard.html', doctor=doctor,
                            cancer_programs=CancerProgram.query.filter_by(
                                doctor_id=doctor_id).all(),
                            clients=Client.query.filter_by(
                                doctor_id=doctor_id).all(),
                            search_results=results,
                            search_term=search_term)

@app.route('/logout')
def logout():
    session.pop('doctor_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
