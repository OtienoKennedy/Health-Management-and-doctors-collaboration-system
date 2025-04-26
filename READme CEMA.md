CEMA System

 Hey there! 👋

This is a web application designed to help manage patient data and treatment programs.  Think of it as a tool for doctors and administrators to keep everything organized.  It's built using Python (Flask) for the backend and includes a web interface.

What it does

Here's a breakdown of what the system can do:

Doctor Management:
    Doctors can log in and access their dashboard.
    The system handles doctor authentication (login) and registration.
Patient Management:
    Doctors can register new patients into the system.
    Each patient has a profile with their name, age, and health record.
    Doctors can view a list of their patients.
    The system includes an API endpoint to retrieve a patient's profile (`/api/clients/<client_id>`).
Cancer Program Management:
    Doctors can create different cancer programs, defining things like stages and duration.
Enrollment:
    Doctors can enroll patients in specific cancer programs.
    The system tracks which programs a patient is enrolled in.
     Doctors can update a patient's progress in a program.
Search:
     Doctors can search for clients by name or ID.

 How it's built

The application is built using these technologies:

Backend: Python, Flask (a web framework)
Database: SQLite (for storing all the data)
Frontend: HTML, CSS, JavaScript (for the web pages)

Setting it up (for developers)

If you want to run this application on your own computer, here's what you need to do:

1.  Make sure you have Python installed.** You'll also need `pip`, which comes with Python.
2.  Install the required Python packages.** Open your terminal or command prompt, go to the directory where you've saved the code, and run this command:
    ```bash
    pip install Flask Flask-SQLAlchemy
    ```
3.  Set up the database.** The application uses SQLite, which doesn't require a separate server.  The database file (`cema_cancer_system.db`) will be created automatically.  However, you need to initialize it:
     python app.py  Or whatever your main Python file is named
    
    This will create the database tables.
4.  Run the application. In your terminal, run:
    python app.py
    `
    This will start the Flask development server.
5.  Open your web browser. Go to `http://127.0.0.1:5000/` to see the application.

 Using the API

The application also has a basic API.  Here's one endpoint you might find useful:

 `GET /api/clients/<client_id>`:  This will return the profile information for a specific client, in JSON format.  You'll need to be logged in as a doctor to use this.

 Important Notes

 This is a simplified application.  A real-world application would likely have more features, better security, and a more robust database.
 The database is stored in a file named `cema_cancer_system.db`.  If you delete this file, you'll lose all the data.
The application includes a login system for doctors.  The first time you log in with a new "Doctor Name", you will also need to provide a "Work Number" to register.  After that, you only need the "Doctor Name" and password.

This application is improvable with time, You can have more features integrted and the structure of the codes are easy to learm. Uploads of features and metrics tracking can be improved- will be done in the next phase