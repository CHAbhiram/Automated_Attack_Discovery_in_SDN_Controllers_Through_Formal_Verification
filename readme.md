# 🛡️ SDN Security Analysis System

A comprehensive web-based platform for analyzing, simulating, and mitigating security threats in Software-Defined Networks (SDN). Built with Django 4.2, MySQL, and Bootstrap 5.


## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Django 4.2.7 |
| Database | MySQL 8.0 |
| Frontend | Bootstrap 5.3, Chart.js, vis.js 4.21 |
| PDF Generation | ReportLab 4.0.7 |
| Network Graph | vis.js CDN |
| Icons | Font Awesome 6.5 |
| Fonts | Google Fonts — Inter |
| Python | 3.11+ |

---

## ✅ Prerequisites

Make sure the following are installed on your system:

- Python 3.11.9 or higher
- MySQL 8.0 or higher

---

### Step 1 — Create a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Configure MySQL database

Log in to MySQL and run:

```sql
CREATE DATABASE sdn_security_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'sdn_user'@'localhost' IDENTIFIED BY 'sdn_password123';
GRANT ALL PRIVILEGES ON sdn_security_db.* TO 'sdn_user'@'localhost';
FLUSH PRIVILEGES;
```

### Step 4 — Run migrations

```bash
python manage.py makemigrations authentication
python manage.py makemigrations network_model
python manage.py makemigrations vulnerability_analysis
python manage.py makemigrations attack_simulation
python manage.py makemigrations reports
python manage.py makemigrations admin_panel
python manage.py makemigrations formal_verification
python manage.py migrate
```

### Step 5 — Generate sample data

```bash
python generate_data.py
```

---

## 👤 Creating the Superuser

The superuser automatically receives the **Admin** role.

```bash
python manage.py createsuperuser
```

Fill in the prompts:
```
Username: admin
Email address: admin@sdn.com
Password: Admin@123
Password (again): Admin@123
```

Then fix the role via shell (first time only):

```bash
python manage.py shell
```

```python
from authentication.models import CustomUser
u = CustomUser.objects.get(username='admin')
u.role = 'admin'
u.save()
exit()
```

---

## ▶️ Running the Application

```bash
python manage.py runserver
```
