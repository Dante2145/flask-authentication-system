from flask import Flask, request,render_template, redirect,session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import datetime
from nmap3 import Nmap
import sqlite3


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'
nmap = Nmap()

                       

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self,email,password,name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(50), unique=True)
    result = db.Column(db.String(100))
    mx_records = db.Column(db.String(100))
    a_records = db.Column(db.String(100))
    txt_records = db.Column(db.String(100))
    ns_records = db.Column(db.String(100))
    sslyze_result = db.Column(db.String(100))
    

    def __init__(self,domain, result, mx_records, a_records,txt_records, ns_records,sslyze_result, scan_date):
        self.domain = domain
        self.result = result
        self.mx_records = mx_records
        self.a_records = a_records
        self.txt_records = txt_records
        self.ns_records = ns_records
        self.sslyze_result = sslyze_result
        self.scan_date = scan_date
        
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(20))
    osmatch = db.Column(db.String(50))
    hostname = db.Column(db.String(50))
    macaddress = db.Column(db.String(50))
    scanType = db.Column(db.String(10))

    def __init__(self, ip_address, osmatch, hostname, macaddress, scanType):
        self.ip_address = ip_address
        self.scanType = scanType
        self.osmatch = osmatch
        self.hostname = hostname
        self.macaddress = macaddress
        
with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        # handle request
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        new_user = User(name=name,email=email,password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')



    return render_template('register.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['email'] = user.email
            return redirect('/dashboard')
        else:
            return render_template('login.html',error='Invalid user')

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if session['email']:
        user = User.query.filter_by(email=session['email']).first()
        return render_template('dashboard.html',user=user)
    
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email',None)
    return redirect('/login')


@app.route('/scan_results')
def scanAll_results():
    query = request.args.get('query')

    conn = sqlite3.connect('./instance/database.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM scan WHERE ip_address LIKE ?", ('%' + query + '%',))
    search_results = cursor.fetchall()
    #cursor.execute("SELECT * FROM scan")
    #data = cursor.fetchall()
    #cursor.execute(f"PRAGMA table_info(scan)")
    #column_info = cursor.fetchall()

    #column_names = [col[1] for col in column_info]
    #print("Column Names:")
    #for name in column_names:
    #    print(name)
    #print(data)
    cursor.close()
    conn.close()

    html_output = "<ul>"
    for row in search_results:
        html_output += f"<li>{row[0]} - {row[1]}</li>"
    html_output +="</ul>"

    return html_output

    

@app.route('/past_results')
def scan_results():
    
    conn = sqlite3.connect('./instance/database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan")
    data = cursor.fetchall()
    cursor.execute(f"PRAGMA table_info(scan)")
    column_info = cursor.fetchall()

    column_names = [col[1] for col in column_info]
    print("Column Names:")
    for name in column_names:
        print(name)
    print(data)
    cursor.close()
    conn.close()

    return render_template('results_template.html', data=data) # data is a list


@app.route('/scan', methods=['POST'])
def scan():
    ip_address = request.form.get('ip_address')
    scanOptions= request.form.get('scanOptions')
    if ip_address:
        try:
            # Run the Nmap scan
            #if scanOptions == "Stealth":
            #scanArg = "-sT"
            #elif 
            nmap_output = nmap.scan_top_ports(ip_address)
            scan_results = nmap_output[ip_address]
            ports = nmap_output[ip_address]['ports']
            #For Database Writing
            if not nmap_output[ip_address]['osmatch']:
                osmatch = "NA"
            else: osmatch = nmap_output[ip_address]['osmatch']

            if not nmap_output[ip_address]['hostname']:
                hostname = "NA"
            else: hostname = nmap_output[ip_address]['hostname']
            
            if not nmap_output[ip_address]['macaddress']:
                macaddress = "NA"
            else: macaddress = nmap_output[ip_address]['macaddress']

            newscanResult = Scan(ip_address=ip_address,osmatch=osmatch, hostname=hostname,macaddress=macaddress, scanType=scanOptions)
            db.session.add(newscanResult)
            db.session.commit()
        
            
            return render_template('scan_results.html', ip_address=ip_address, ports=ports, scan_results=scan_results, scanOptions=scanOptions)
        except Exception as e:
            return f"Error: {str(e)}"
    else:
        return "Please provide an IP address to scan."

if __name__ == '__main__':
    app.run(debug=True)