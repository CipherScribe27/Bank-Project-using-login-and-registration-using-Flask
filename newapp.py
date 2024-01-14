from flask import Flask, render_template, url_for, redirect, request, session,make_response,jsonify,send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, create_engine, desc
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, length, ValidationError,EqualTo, Email, Regexp
from flask_bcrypt import Bcrypt
from datetime import timedelta
import logging
import re
from datetime import datetime
from sqlalchemy.orm import sessionmaker, joinedload
import csv

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
# bank_app = Flask(__name__)

# db2 = SQLAlchemy(bank_app)

# def init_db1(app):
#     db1.init_app(app)
#     db1.create_all(bind=['bank'])
#     db1.create_all()

# def init_db2(app):
#     db2.init_app(app)
#     db2.create_all()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY']= 'thisisasecretkey'

# app.config['SQLALCHEMY_BINDS'] = {
#     'login_register':'sqlite:///login.db',
#     'bank': 'sqlite:///bank.db'
# }

# init_db1(app)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.bd'
# bank_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# init_db2(bank_app)

db1 = SQLAlchemy(app)


# app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///bank.bd'
# app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
# db = SQLAlchemy(app)

# bank_app = Flask(__name__)
# bank_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.bd'
# bank_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# bank_db = SQLAlchemy(bank_app)
# bank_db.init_app(bank_app)


class User(db1.Model):
    # __bind_key__ = 'bank'
    id = db1.Column(db1.Integer,primary_key = True, autoincrement = True)
    name = db1.Column(db1.String(),nullable = True)
    account_number = db1.Column(db1.String(),unique =True, nullable = True)
    current_balance = db1.Column(db1.Float(), default = 0.0)


class Transaction(db1.Model):
    # __bind_key__ = 'bank'
    si_no = db1.Column(db1.Integer,primary_key = True, autoincrement = True)
    account_number = db1.Column(db1.String(),nullable = True)
    amount = db1.Column(db1.Float(),nullable =True)
    transaction_type = db1.Column(db1.String())
    timestamp = db1.Column(db1.DateTime,default = datetime.utcnow)

# Extend the session timeout (optional)
app.permanent_session_lifetime = timedelta(days=7)  # Extend the session to 7 days

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class Users(db1.Model, UserMixin):
    # __bind_key__ = 'login_register'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), nullable=False)
    username = Column(String(20), nullable=False, unique=True)
    email = Column(String(50), nullable=False, unique=True)
    phone_number = Column(String(15), nullable=False)
    password = Column(String(80), nullable=False)

    def __init__(self, name, username, email, phone_number, password):
        self.name = name
        self.username = username
        self.email = email
        self.phone_number = phone_number
        self.password = password

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)


    
class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), length(min=4, max=50)], render_kw={"placeholder": "Name"})
    username = StringField('Username', validators=[InputRequired(), length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField('Email', validators=[InputRequired(), Email(), length(max=50)], render_kw={"placeholder": "Email"})
    phone_number = StringField('Phone Number', validators=[InputRequired(), length(min=10, max=15),\
                    Regexp(r'^[0-9]*$', message="Phone number must only contain digits")], render_kw={"placeholder": "Phone Number"})
    password = PasswordField('Create Password', validators=[InputRequired(), length(min=4, max=20)], render_kw={"placeholder": "Create Password"})
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords must match')], render_kw={"placeholder": "Confirm Password"})
    
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = Users.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different name")

    def validate_email(self, email):
        existing_user_email = Users.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email address is already registered. Please use a different email")

    def validate_phone_number(self, phone_number):
        # You can add additional validation for phone number if needed
        if not phone_number.data.isdigit():
            raise ValidationError("Phone number must only contain digits.")

        # Check if the phone number has a valid length (adjust as needed)
        min_length = 10
        max_length = 15
        if not min_length <= len(phone_number.data) <= max_length:
            raise ValidationError(f"Phone number must be between {min_length} and {max_length} digits.")
        else:
            pass
    
    def validate_confirm_password(self, confirm_password):
        if self.password.data != confirm_password.data:
            raise ValidationError("Passwords must match")
    

    
    
class LoginForm(FlaskForm):
    username = StringField(validators = [InputRequired(), length(min = 4, max = 20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators = [InputRequired(), length(min = 4, max = 20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")
    

@app.route('/')
def home():
    return render_template("home.html")



@app.route('/login', methods = ['GET','POST'])
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            user = Users.query.filter_by(username = form.username.data).first()
            if user:
                session['username'] = form.username.data
                session['password'] = form.password.data
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user,remember=False)
                    return redirect('/dashboard', code=301)
    else:
        if 'username' in session:
            return redirect('dashboard')
        return render_template("login.html",form = form)


@app.route('/add',methods=["GET","POST"])
def add_user():
    if request.method == "POST":
        name = request.form['name']
        account_number = request.form['account_number']
        current_balance = float(request.form['current_balance'])

        db1.session.add(User(name = name, account_number = account_number, current_balance = current_balance))
        db1.session.commit()
        return redirect(url_for('add_user',message = "Account Created Successfully"))
    
    return render_template("add_user.html",message = request.args.get('message'))


@app.route('/deposit',methods = ["GET","POST"])
def deposit():
    if request.method == "POST":
        account_number = request.form.get("account_number")
        amount = float(request.form.get('amount'))

        user = User.query.filter_by(account_number = account_number).first()
        if not user:
            return render_template('deposit.html',message1="user not Found")
        
        user.current_balance += amount
        db1.session.add(Transaction(account_number = account_number,amount = amount, transaction_type = "Deposit"))
        db1.session.commit()
 
        return render_template('deposit.html',message = 'Deposit Successful', current_balance = user.current_balance)
    return render_template("deposit.html")

@app.route('/withdraw',methods= ["GET","POST"])
def withdraw():
        
    if request.method == "POST":  
        account_number = request.form.get("account_number")
        amount = float(request.form.get("amount"))

        user = User.query.filter_by(account_number = account_number).first()

        if not user:
            return render_template("withdraw.html",message1="user not Found")
        
        if user.current_balance < amount:
            return render_template("withdraw.html",message1="Insufficient Fund")
        
        user.current_balance -= amount
        db1.session.add(Transaction(account_number = account_number, amount = amount, transaction_type = "Withdrawl"))
        db1.session.commit()
        return render_template("withdraw.html",message = "Withdraw Successfully", current_balance = user.current_balance)
    return render_template("withdraw.html")

@app.route('/ministatement', methods=["GET", "POST"])
def ministatement():
    if request.method == "POST":
        account_number = request.form.get('account_number')
        user = User.query.filter_by(account_number=account_number).first()

        if not user:
            return render_template("mini_statement.html", message1="User Not Found")

        data = (db1.session.query(User, Transaction).join(Transaction, User.account_number == Transaction.account_number)
                .filter(User.account_number == account_number)
                .order_by(desc(Transaction.timestamp)).all())
        user, transactions = data[0]

        csv_f = [["Amount", "TransactionType", "Timestamp", "current_balance"]]
        i = 1
        path = f"mini_statement_{account_number}--{i}.csv"
        with open(path, 'a', newline='', encoding="utf-8") as file:
            csv_writer = csv.writer(file)
            if file.tell() == 0:  # Check if the file is empty
                csv_writer.writerows(csv_f)
            csv_writer.writerow([transactions.amount, transactions.transaction_type, transactions.timestamp, user.current_balance])
            i += 1

        return send_file(path, as_attachment=True, download_name=f"mini_statement_{account_number}.csv")
    return render_template("mini_statement.html")


@app.route('/dashboard', methods = ['GET','POST'])
@login_required
def dashboard():
    return render_template('index.html')
    # if request.method == 'POST':
    #     if request.form.get('logout_button'):
    #         logout_user()
    #         return redirect(url_for('login'))  # Redirect to the login page after logout
    #     else:
    #         pass


    # You can access the current user's attributes like username
    # username = current_user.username
    #flash("Welcome, {}!".format(username))
    # return render_template('success.html', username=username)
    # return render_template('success.html')



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    if request.method == 'POST':
        session.clear()
        logout_user()
        # return redirect('login',code = 301)
        form = LoginForm()
        return render_template('login.html', form=form)
    


@app.route('/register', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        # Store user data in session (temporary storage)
        # session['username'] = form.username.data
        # session['email'] = form.email.data
        # session['phone_number'] = form.phone_number.data
        # session['password'] = form.password.data
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # new_user = User(username= form.username.data, password = hashed_password)
                # Create a new User object and add it to the database
        new_user = Users(
            name=form.name.data,
            username=form.username.data,
            email=form.email.data,
            phone_number=form.phone_number.data,
            password=hashed_password
        )
        db1.session.add(new_user)
        db1.session.commit()
        # You may want to redirect to a different page or perform additional actions
        return redirect(url_for('login',form=LoginForm()))

    return render_template("signup.html", form = form)



# Store the current user's details in the session
@app.before_request
def get_current_user():
    if current_user.is_authenticated:
        session['current_user'] = current_user.username
    else:
        session.pop('current_user', None)
        
@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_code=500, error_message="Internal Server Error"), 500


    
if __name__ == "__main__":
    with app.app_context():
        try:
            db1.create_all()
            # db1.create_all(bind=['bank'])
            # db1.create_all(bind=['login_register'])
            # init_db2(bank_app)
            # db.create_all()
            # db.drop_all()
            logging.info("Database tables created successfully.")
        except Exception as e:
            logging.error(f"Database table creation failed: {str(e)}")
    app.run(debug=True,port = 3000)
    
