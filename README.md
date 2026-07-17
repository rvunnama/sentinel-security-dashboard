# Sentinel

Sentinel is a Flask-based cybersecurity dashboard that monitors authentication activity, detects suspicious login behavior, and provides administrators with real-time security analytics through an interactive web interface.

---

## Demo

Live Demo: *(Coming Soon)*

GitHub Repository:
https://github.com/rvunnama/sentinel-security-dashboard

---

## Features

- Secure user authentication with hashed passwords
- Interactive analytics dashboard
- Automated threat detection
  - **LOW:** Login from a previously unseen IP address
  - **MEDIUM:** Three failed login attempts under 10 minutes
  - **HIGH:** Five failed login attempts under 10 minutes
- Authentication statistics and visualizations
- Login history and security audit logging
- Responsive Bootstrap interface

---

## Screenshots

### Landing Page

*<img width="1412" height="813" alt="home-page" src="https://github.com/user-attachments/assets/1d4eed70-4b55-4a54-b5fd-f704aca0bfd3" />*

### Dashboard

*<img width="1467" height="830" alt="dashboard-ui-v1" src="https://github.com/user-attachments/assets/96c31b5e-133b-4f07-8d76-dbeb88430f8a" />*

### Login

*<img width="1422" height="795" alt="login-page" src="https://github.com/user-attachments/assets/f5cd5a56-f970-42df-a408-3493bd983356" />*

---

## Technology Stack

- Python
- Flask
- SQLite
- Bootstrap 5
- Chart.js
- HTML/CSS
- Werkzeug Password Hashing

---

## Project Structure

...

sentinel-security-dashboard/
|
├── app.py
├── database.py
├── requirements.txt
│
├── static/
│   ├── css/
│   └── screenshots/
│
├── templates/
│
└── database/
```

---

## Running Locally

Clone the repository

```bash
git clone https://github.com/rvunnama/sentinel-security-dashboard.git
```

Navigate into the project

```bash
cd sentinel-security-dashboard
```

Create a virtual environment

```bash
python -m venv .venv
```

Activate it

Mac/Linux

```bash
source .venv/bin/activate
```

Windows

```bash
.venv\Scripts\activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python app.py
```

Visit

```
http://127.0.0.1:5000
```

---

## Future Improvements

- Email notifications for critical alerts
- Multi-factor authentication
- User roles and permissions
- Threat intelligence integration
- Docker deployment
- PostgreSQL support

---

## About

Sentinel was built to explore secure authentication, cybersecurity monitoring, and full-stack web development with Flask. The project emphasizes real-time threat detection, data visualization, and user-focused interface design.
