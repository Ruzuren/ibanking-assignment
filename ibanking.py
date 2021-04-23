from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from sqlalchemy import text
import base64
import uuid
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.sql import text

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres:123456@localhost:5432/ibanking'
app.config['SECRET_KEY']='secret'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
conn_str = 'postgresql://postgres:123456@localhost:5432/ibanking'
engine = create_engine(conn_str, echo=False)

#################################################################################################

class Userz(db.Model):
    user_id = db.Column(db.String, primary_key = True, nullable = False) # PK
    user_name = db.Column(db.String(25), nullable = False, unique = True)
    full_name = db.Column(db.String(45), nullable = False)
    email = db.Column(db.String(45), nullable = False, unique = True)
    password = db.Column(db.String, nullable = False)
    is_admin = db.Column(db.Boolean, default = False)
    user_acc = db.relationship('Account', backref = 'x', lazy = 'dynamic') # BR

class Branch(db.Model):
    branch_number = db.Column(db.String(4), primary_key = True, nullable = False) # PK
    branch_name = db.Column(db.String(25), nullable = False, unique = True)
    branch_address = db.Column(db.String(25), nullable = False)
    branch_acc = db.relationship('Account', backref = 'y', lazy = 'dynamic') # BR
    branch_tra = db.relationship('Transaction', backref = 'yy', lazy = 'dynamic') # BR

class Account(db.Model):
    account_number = db.Column(db.Integer, primary_key = True, nullable = False, unique = True) # PK
    account_type = db.Column(db.String(25), nullable = False, default = "Regular") 
    account_balance = db.Column(db.Integer, nullable = False)
    last_transaction = db.Column(db.DateTime, nullable = False)
    user_id = db.Column(db.String, db.ForeignKey('userz.user_id'), nullable = False) # FK
    branch_id = db.Column(db.String, db.ForeignKey('branch.branch_number'), nullable = False) # FK
    account_tra = db.relationship('Transaction', backref = 'z', lazy = 'dynamic') # BR

class Transaction(db.Model):
    transaction_id = db.Column(db.Integer, primary_key = True, index =True) # PK
    transaction_type = db.Column(db.String(25), nullable = False)
    transaction_date = db.Column(db.DateTime, nullable = False)
    transaction_ammount = db.Column(db.Integer, nullable = False)
    transaction_description = db.Column(db.String(255))
    transaction_sender = db.Column(db.Integer, nullable = True)
    transaction_sender_branch = db.Column(db.String(25), nullable = True)
    branch_id = db.Column(db.String, db.ForeignKey('branch.branch_number'), nullable = False) # FK
    account_id = db.Column(db.Integer, db.ForeignKey('account.account_number'), nullable = False) # FK

#################################################################################################
# Auth

def get_hash(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def authz():
    token = request.headers.get('Authorization')
    token2 = token.replace("Basic ","")
    plain = base64.b64decode(token2).decode('utf-8')
    auth_data = plain.split(":")
    return auth_data

def get_username(auth_data):
    username = auth_data[0]
    return username

def check_user(auth_data):
    user = Userz.query.filter_by(user_name=auth_data[0]).first()
    a = False
    if user is None :
        return a #returns false

def get_password(auth_data):
    user = Userz.query.filter_by(user_name=auth_data[0]).first()
    password = bcrypt.generate_password_hash(auth_data[1]).decode('utf-8')
    hashcheck = bcrypt.check_password_hash(user.password, password)
    return hashcheck #returns true if valid

def get_is_admin(auth_data):
    user = Userz.query.filter_by(user_name=auth_data[0]).first()
    if user.is_admin:
        return True

#################################################################################################
# User

def get_userData(id):
    return Userz.query.filter_by(user_id=id).first_or_404()

def return_user(u):
    return {'User id' : u.user_id,'Username':u.user_name,'Full name':u.full_name, 'Email' : u.email, 'is admin': u.is_admin}

#################################################################################################
# Branch

def get_branchData(id):
    return Branch.query.filter_by(branch_number = id).first_or_404()

def return_branch(b):
    return {'Branch Number': b.branch_number, 'Branch Name': b.branch_name, 'Branch Address': b.branch_address}

#################################################################################################
# Account

def get_accountData(id):
    return Account.query.filter_by(account_number=id).first_or_404()

def return_account(a):
    return {'Account Number': a.account_number, "Full Name":a.x.full_name, "Branch ID": a.y.branch_number, 
    "Account Balance":a.account_balance, "Branch Name":a.y.branch_name, "Last Transaction": a.last_transaction}

#################################################################################################
# Transaction

def get_transactionData(id):
    return Transaction.query.filter_by(transaction_id=id).first_or_404()

def return_transaction(t):
    acc = Account.query.filter_by(account_number=t.account_id).first()
    return {'Transaction ID': t.transaction_id, "Transaction Date": t.transaction_date, "Transaction Type": t.transaction_type,
    "Related account":t.account_id, "Full Name": acc.x.full_name}

def return_save(t):
    return {'Transaction ID': t.transaction_id, 'Transaction Date': t.transaction_date, 'Transaction Type': t.transaction_type,
    "Target Branch":"", "Target Account":"", "Transaction Ammount": t.transaction_ammount, "Account Balance":""}

def return_transfer(t):
    return {'Transaction ID': t.transaction_id, 'Transaction Date': t.transaction_date, 'Transaction Type': t.transaction_type,
    "From":"" , "Target Branch":"", "Target Account":"", "Transaction Ammount": t.transaction_ammount, "Description": t.transaction_description }

def return_withdraw(t):
    return {'Transaction ID': t.transaction_id, "Transaction Date": t.transaction_date, "Transaction Type": t.transaction_type,
    "Transaction Ammount": t.transaction_ammount, "Account Balance":""}

#################################################################################################
# Reporting

#################################################################################################
################################## ENDPOINT USERZ ###############################################
#################################################################################################

# make admin
@app.route('/admin/', methods = ["POST"])
def make_admin():
    data= request.get_json()
    hash = get_hash(data['password'])
    u = Userz(
        user_name= data['user_name'],
        user_id = str(uuid.uuid4()),
        full_name= data['full_name'],
        email= data['email'],
        is_admin= data.get('is_admin', False),
        password= hash
    )
    db.session.add(u)
    db.session.commit()
    return  return_user(u), 201

# list all users (Admin)
@app.route('/users/', methods = ["GET"])
def get_users():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
            }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
            }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                return jsonify([return_user(user) for user in Userz.query.all()]), 201

# search user by id (Admin)
@app.route('/users/<id>/', methods = ["GET"])
def get_user(id):
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                user = get_userData(id)
                return return_user(user), 201

# create new user (Admin)
@app.route('/users/', methods=['POST'])
def create_user():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                data = request.get_json()
                if not 'user_name' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'user_name is not given'
                    }), 400
                if not 'email' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'email is not given'
                    }), 400
                if not 'full_name' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'user_name is not given'
                    }), 400
                if not 'password' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'password is not given'
                    }), 400
                if len(data['user_name']) < 4:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'Username must contain a minimum of 4 characters'
                    }), 400
                if len(data['email']) < 6:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'Email must contain a minimum of 6 characters'
                    }), 400
                if len(data['password']) < 8:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'Password must contain at least 8 characters'
                    }), 400
                hash = get_hash(data['password'])
                u = Userz(
                        user_name= data['user_name'],
                        full_name= data['full_name'],
                        user_id = str(uuid.uuid4()),
                        email= data['email'],
                        is_admin= data.get('is_admin', False),
                        password= hash
                    )
                db.session.add(u)
                db.session.commit()
                return  return_user(u), 201

# update / edit user data by id (Admin)
@app.route('/users/<id>/', methods=['PUT'])
def update_user(id):
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                data = request.get_json()
                user = get_userData(id)
                if 'user_name' in data:
                    user.user_name=data['user_name']
                if 'full_name' in data:
                    user.full_name=data['full_name']
                if 'email' in data:
                    user.email=data['email']
                if 'is admin' in data:
                    user.is_admin=data['is_admin']
                if 'password' in data:
                    user.password = get_hash(data['password'])
                db.session.commit()
                return jsonify({'Success': 'User data has been updated'}, return_user(user))

# delete / close user data by id (Admin)
@app.route('/users/<id>/', methods=['DELETE'])
def delete_user(id):
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                user = Userz.query.filter_by(user_id=id).first_or_404()
                db.session.delete(user)
                db.session.commit()
                return {'success': 'User data deleted successfully'}
#################################################################################################
################################## ENDPOINT BRANCH ##############################################
#################################################################################################

# list all branches (Admin)
@app.route('/branch/', methods = ["GET"])
def get_branches():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                return jsonify([return_branch(branches) for branches in Branch.query.all()
                ]), 201

# search branch by id (Admin)
@app.route('/branch/<id>/', methods = ["GET"])
def get_branch(id):
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                branch = get_branchData(id)
                return return_branch(branch), 201

# create new branch (Admin)
@app.route('/branch/', methods=['POST'])
def create_branch():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                data = request.get_json()
                if not 'branch_name' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'branch_name is not given'
                    }), 400
                if not 'branch_address' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'branch_address is not given'
                    }), 400
                if not 'branch_number' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'branch_number is not given'
                    }), 400
                if len(data['branch_name']) < 4:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'branch_name must contain a minimum of 4 letters'
                    }), 400
                if len(data['branch_number']) < 4:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'branch_number must contain a minimum of 4 letters'
                    }), 400
                if len(data['branch_address']) < 6:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'branch_address must contain a minimum of 6 letters'
                    }), 400
                b = Branch(
                        branch_name = data['branch_name'],
                        branch_number = data['branch_number'],
                        branch_address = data['branch_address']
                    )
                db.session.add(b)
                db.session.commit()
                return  return_branch(b), 201

# update / edit branch by id (Admin)
@app.route('/branch/<id>/', methods=['PUT'])
def update_branch(id):
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                data = request.get_json()
                branch = get_branchData(id)
                if 'branch_name' in data:
                    branch.branch_name=data['branch_name']
                if 'branch_address' in data:
                    branch.branch_address=data['branch_address']
                db.session.commit()
                return jsonify({'Success': 'Branch data has been updated'}, return_branch(branch)), 201

# delete / close branch by id (Admin)
@app.route('/branch/<id>/', methods=['DELETE'])
def delete_branch(id):
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                branch = Branch.query.filter_by(branch_id=id).first_or_404()
                db.session.delete(branch)
                db.session.commit()
                return {'success': 'Branch data deleted successfully'}

#################################################################################################
################################## ENDPOINT ACCOUNT #############################################
#################################################################################################

# list all accounts (Admin)
@app.route('/account/', methods = ["GET"])
def get_accounts():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                return jsonify([return_account(accounts) for accounts in Account.query.all()
                ])

# seach account by id (Admin)
@app.route('/account/<id>/', methods = ["GET"])
def get_account(id):
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                account = get_accountData(id)
                return return_account(account)

# create account (Admin)
@app.route('/account/', methods=['POST'])
def create_account():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                data = request.get_json()
                if not 'deposit' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'deposit is not given'
                    }), 400
                if not 'date' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'date is not given'
                    }), 400
                if not 'account_number' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'account_number is not given'
                    }), 400
                if data["deposit"] < 150000:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'First deposit must larger than or equal to 150000'
                    }), 400
                else: # >= 150000
                    a = Account(
                            account_number = data['account_number'],
                            account_type = data['account_type'],
                            account_balance = data['deposit'],
                            last_transaction = data['date'],
                            user_id = data["user id"],
                            branch_id = data["branch_id"]
                        )
                    # when opening a new account, this will be counted as deposit in Transaction table
                    t = Transaction(
                          transaction_type = "save",
                          transaction_date = data['date'],
                          transaction_ammount = data['deposit'],
                          account_id = data['account_number'],
                          branch_id = data['branch_id']
                    )
                    db.session.add(a)
                    db.session.add(t)
                    db.session.commit()
                    return  return_account(a), 201

# update / edit account by id (Admin)
@app.route('/account/<id>/', methods=['PUT'])
def update_account(id):
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                data = request.get_json()
                account = get_accountData(id)
                if 'owner_id' in data:
                    account.owner_id=data['owner_id']
                if 'account_type' in data:
                    account.account_type=data['account_type']
                if 'account_balance' in data:
                    account_account_balance=data['account_balance']
                db.session.commit()
                return jsonify({'Success': 'Account data has been updated'}, return_account(account))

# delete account (Admin)
@app.route('/account/<id>/', methods=['DELETE'])
def delete_account(id):
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                account = Account.query.filter_by(account_id=id).first_or_404()
                db.session.delete(account)
                db.session.commit()
                return {
                    'success': 'This bank account has been closed'
                }

#################################################################################################
################################## ENDPOINT TRANSACTION #########################################
#################################################################################################

# List all transactions (Admin)
@app.route('/transaction/', methods = ["GET"])
def get_transactions():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                return jsonify([return_transaction(transactions) for transactions in Transaction.query.all()
                ])

# Search Transaction by id (Admin)
@app.route('/transaction/<id>/', methods = ["GET"])
def get_transaction(id):
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                # transaction = get_transactionData(id)
                trans = Transaction.query.filter_by(transaction_id=id).first_or_404()
                acc = Account.query.filter_by(account_number=trans.account_id).first()
                # user = Userz.query.filter_by(user_id=user_id).first()
                # return return_transaction(transaction)
                return jsonify([ {'Transaction ID': trans.transaction_id, "Transaction Date": trans.transaction_date, "Transaction Type": trans.transaction_type,
                        "Related account":trans.account_id, "Full Name": acc.x.full_name} ])

# save / deposit (Admin)
@app.route('/transaction/deposit/', methods = ["POST"])
def save_money():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                data=request.get_json()
                if not 'transaction_type' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'transaction_type is not given'
                    }), 400
                else:
                    if data['transaction_type'] == "save":
                        if not 'transaction_ammount' in data:
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'transaction_ammount is not given'
                            }), 400
                        if not 'transaction_date' in data:
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'transaction_date is not given'
                            }), 400
                        if not 'account_id' in data:
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'account_id is not given'
                            }), 400
                        if not 'branch_id' in data:
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'branch_id is not given'
                            }), 400
                        t = Transaction(
                            transaction_type = data['transaction_type'],
                            transaction_date = data['transaction_date'],
                            transaction_ammount = data['transaction_ammount'],
                            account_id = data['account_id'],
                            branch_id = data['branch_id']
                        )
                        db.session.add(t)
                        acc = Account.query.filter_by(account_number=data['account_id']).first()
                        temp = acc.account_balance
                        temp2 = temp + data['transaction_ammount']
                        acc.account_balance = temp2
                        acc.last_transaction = data['transaction_date']
                        db.session.commit()
                        branch = Branch.query.filter_by(branch_number=data['branch_id'])
                        user = Userz.query.filter_by(user_id=acc.user_id)
                        return jsonify([
                            {
                                "1. Transaction summary": {
                                    "Transaction ID": t.transaction_id,
                                    "Transaction Date": t.transaction_date,
                                    "Transaction Type": t.transaction_type,
                                },
                                "2. Account information": {
                                    "Account Number": t.account_id,
                                    "Ammount Deposited": data['transaction_ammount'],
                                    "Account Balance": t.z.account_balance,
                                    "Full Name": acc.x.full_name
                                }
                            }
                        ]), 201

# Transfer (User)
@app.route('/transaction/transfer/', methods = ["POST"])
def transfer_money():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true        
            if get_is_admin(login): #if true (if admin)
                return jsonify({
                'error' : 'Bad Request',
                'message' : "Admins cannot execute user's endpoints"
                }), 400
            else: #if false (not admin)
                data=request.get_json()
                if not 'transaction_type' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'transaction_type is not given'
                    }), 400
                else:
                    if data['transaction_type'] == "transfer":
                        if not 'transaction_ammount' in data:
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'transaction_ammount is not given'
                            }), 400
                        if not 'transaction_date' in data:
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'transaction_date is not given'
                            }), 400
                        if not 'target_account' in data: # target
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'target_account is not given'
                            }), 400
                        if not 'target_branch' in data: #target
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'target_branch is not given'
                            }), 400
                        if not 'transaction_sender' in data: #sender
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'transaction_target is not given'
                            }), 400
                        if not 'transaction_sender_branch' in data: #sender
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'transaction_target_branch is not given'
                            }), 400
                        acc_test = Account.query.filter_by(account_number=data['transaction_sender']).first()
                        if acc_test.account_balance < data['transaction_ammount']: # insufficent balance
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'Insufficent account balance to do this operation'
                            }), 400
                        else: 
                            tempx = acc_test.account_balance
                            tempx1 = tempx - data['transaction_ammount']
                            if tempx1 < 150000: # balance will be less than minimum account ballance required
                                return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'Your balance will be less than the minimum account balance required if you do this operation'
                                }), 400
                            else:
                                t = Transaction(
                                    transaction_type = data['transaction_type'], #transfer
                                    transaction_date = data['transaction_date'], #date
                                    transaction_ammount = data['transaction_ammount'], #duit
                                    account_id = data['target_account'], 
                                    branch_id = data['target_branch'],
                                    transaction_sender = data['transaction_sender'],
                                    transaction_sender_branch = data['transaction_sender_branch']
                                )
                                # add error handling kalo balance transfer > balance account sender !< minimum balance
                                db.session.add(t)

                                # update balance sender
                                acc = Account.query.filter_by(account_number=data['transaction_sender']).first()
                                # temp = acc.account_balance
                                # temp2 = temp - data['transaction_ammount']
                                temp2 = acc.account_balance - data['transaction_ammount']
                                acc.account_balance = temp2
                                acc.last_transaction = data['transaction_date']

                                # update balance receiver
                                acc1 = Account.query.filter_by(account_number=data['target_account']).first()
                                # temp = acc1.account_balance
                                # temp2 = temp + data['transaction_ammount']
                                temp2 = acc1.account_balance + data['transaction_ammount']
                                acc1.account_balance = temp2

                                # commit
                                db.session.commit()

                                # data sender
                                branch = Branch.query.filter_by(branch_number=data['transaction_sender'])
                                user = Userz.query.filter_by(user_id=acc.user_id)

                                # data receiver
                                branch1 = Branch.query.filter_by(branch_number=data['target_branch'])
                                user1 = Userz.query.filter_by(user_id=acc1.user_id)

                                return jsonify([
                                    {
                                        "1. Transaction summary": {
                                            "Transaction ID": t.transaction_id,
                                            "Transaction Date": t.transaction_date,
                                            "Transaction Type": t.transaction_type,
                                        },
                                        "2. Sender information": {
                                            "Account Number": t.transaction_sender,
                                            "Ammount Transferred": data['transaction_ammount'],
                                            # "Account Balance": acc.z.account_balance,
                                            "Full Name": acc.x.full_name
                                        },
                                        "3. Receiver information": {
                                            "Account Number": t.account_id,
                                            "Full Name": acc1.x.full_name
                                        }
                                    }
                                ]), 201

# Withdraw (User)
@app.route('/transaction/withdraw/', methods = ["POST"])
def withdraw_money():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if get_is_admin(login): #if true (if admin)
                return jsonify({
                'error' : 'Bad Request',
                'message' : "Admins cannot execute user's endpoints"
                }), 400
            else: #if false (not admin)
                data=request.get_json()
                if not 'transaction_type' in data:
                    return jsonify({
                        'error' : 'Bad Request',
                        'message' : 'transaction_type is not given'
                    }), 400
                else:
                    if data['transaction_type'] == "withdraw":
                        if not 'transaction_ammount' in data:
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'transaction_ammount is not given'
                            }), 400
                        if not 'transaction_date' in data:
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'transaction_date is not given'
                            }), 400
                        if not 'account_id' in data:
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'account_id is not given'
                            }), 400
                        if not 'branch_id' in data:
                            return jsonify({
                                'error' : 'Bad Request',
                                'message' : 'branch_id is not given'
                            }), 400
                        t = Transaction(
                            transaction_type = data['transaction_type'],
                            transaction_date = data['transaction_date'],
                            transaction_ammount = data['transaction_ammount'],
                            account_id = data['account_id'],
                            branch_id = data['branch_id']
                        )
                        db.session.add(t)
                        acc = Account.query.filter_by(account_number=data['account_id']).first()
                        temp = acc.account_balance
                        temp2 = temp - data['transaction_ammount']
                        acc.account_balance = temp2
                        acc.last_transaction = data['transaction_date']
                        db.session.commit()
                        branch = Branch.query.filter_by(branch_number=data['branch_id'])
                        user = Userz.query.filter_by(user_id=acc.user_id)
                        return jsonify([
                            {
                                "1. Transaction summary": {
                                    "Transaction ID": t.transaction_id,
                                    "Transaction Date": t.transaction_date,
                                    "Transaction Type": t.transaction_type,
                                },
                                "2. Account information": {
                                    "Account Number": t.account_id,
                                    "Ammount Debitted": data['transaction_ammount'],
                                    "Account Balance": t.z.account_balance,
                                    "Full Name": acc.x.full_name
                                }
                            }
                        ]), 201

# See Transaction History by id (User)
@app.route('/transaction/history/', methods = ["GET"])
def get_history():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if get_is_admin(login): #if true (if admin)
                return jsonify({
                'error' : 'Bad Request',
                'message' : "Admins cannot execute user's endpoints"
                }), 400
            else: #if false (not admin)
                # can only view his own data
                user = Userz.query.filter_by(user_name = login[0]).first()
                account = Account.query.filter_by(user_id = user.user_id).first()
                transaction = Transaction.query.filter_by(account_id = account.account_number).all()
                # return jsonify([return_transaction(trans) for trans in transaction ])

                
                return jsonify([
                    {
                        "Transaction ID" : trans.transaction_id,
                        "Transaction Type" : trans.transaction_type,
                        "Transaction Date" : trans.transaction_date,
                        "Transaction Ammount" : trans.transaction_ammount,
                        "Transaction Description" : trans.transaction_description,
                        "Transaction Sender" : trans.transaction_sender,
                        "Transaction Receiver" : trans.account_id
                    }for trans in transaction
                ])

# See Account info / see remaining balance by id (User)
@app.route('/account/user/', methods = ["GET"])
def get_user_account():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if get_is_admin(login): #if true (if admin)
                return jsonify({
                'error' : 'Bad Request',
                'message' : "Admins cannot execute user's endpoints"
                }), 400
            else: #if false (not admin)
                # can only view his own data
                user = Userz.query.filter_by(user_name=login[0]).first()
                account = Account.query.filter_by(user_id = user.user_id).first()
                return return_account(account)

# transfer dan withdraw jangan sampai kurang dari min. balance (150k)
# admin gabisa menjalankan fitur" user (transfer, dll)

#################################################################################################
################################## ENDPOINT REPORTING ###########################################
#################################################################################################

# filter by period (start date / end date) : number of accounts, number of users, total debit, credit, balance
@app.route('/transaction/period/', methods = ["GET"])
def get_by_period():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                data = request.get_json()
                if not "start_period" in data:
                    return jsonify({
                                'error' : 'Bad Request',
                                'message' : "start_period is not given"
                            }), 400
                if not "end_period" in data:
                    return jsonify({
                                'error' : 'Bad Request',
                                'message' : "end_period is not given"
                            }), 400
                else:
                    
                    transaction = Transaction.query.filter((Transaction.transaction_date).between(data['start_period'], data['end_period'])).all()
                    return jsonify([
                        {
                            "Transaction ID": trans.transaction_id,
                            "Transaction Type": trans.transaction_type,
                            "Transaction Date": trans.transaction_date,
                            "Transaction ammount": trans.transaction_ammount,
                            "Transaction sender": trans.transaction_sender,
                            "Transaction receiver": trans.account_id
                        } for trans in transaction
                    ])

# account number
@app.route('/account/number/', methods = ["GET"])
def get_account_number():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                return jsonify({
                'The number of registered accounts are' : Account.query.count()
                }), 201

# total debit (withdraw) (admin)
@app.route('/transaction/debit/', methods = ["GET"])
def get_total_debit():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                # trans = Transaction.query.filter(Transaction.transaction_type == "withdraw").all()
                # return jsonify({
                # 'The total debit is' : Transaction.query.filter(Transaction.transaction_type == "withdraw").sum()
                # }), 201
                all = []
                with engine.connect() as connection:
                    qry = text("SELECT sum(transaction_ammount) FROM Transaction where transaction_type = 'withdraw' ")
                    result = connection.execute(qry)
                    for i in result:
                        all.append({
                            'The total debit is':i[0]
                        })
                    return jsonify(all) # error karena transaction_ammount di tabel ini VARCHAR

# total credit (deposit) (Admin)
@app.route('/transaction/credit/', methods = ["GET"])
def get_total_transfer():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                all = []
                with engine.connect() as connection:
                    qry = text("SELECT sum(transaction_ammount) FROM Transaction where transaction_type = 'save' ")
                    result = connection.execute(qry)
                    for i in result:
                        all.append({
                            'The total credit is':i[0]
                        }) # error karena transaction_ammount di tabel ini VARCHAR
                    return jsonify(all)

# total balance (user balance) (Admin)
@app.route('/account/balance/', methods = ["GET"])
def get_total_balance():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                all = []
                with engine.connect() as connection:
                    qry = text("SELECT sum(account_balance) FROM Account")
                    result = connection.execute(qry)
                    for i in result:
                        all.append({
                            'The total balance is':i[0]
                        })
                    return jsonify(all)

# user number
@app.route('/user/number/', methods = ["GET"])
def get_user_number():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                return jsonify({
                'The number of registered users are' : Userz.query.count()
                }), 201

def get_dormant_period(a, b): # data["today's_date"], acc.last_transaction
    data1, data2 = a, b
    a = a.split("-")
    # b = b.split("-")
    y1, m1, d1 = int(a[0]), int(a[1]), int(a[2])
    # y2, m2, d2 = int(b[0]), int(b[1]), int(b[2])
    y2, m2, d2 = b.year, b.month, b.day
    # if y1 > y2:
    if m1 < m2:
        y1 -= 1
        m1 += 12 # 12 months in a year
        if d1 < d2:
            m1 -= 1
            d1 += 30 # imagine all months have 30 days
            count_y = y1 - y2
            count_m = m1 - m2
            count_d = d1 - d2
            return {
                "Year(s)": count_y,
                "Month(s)": count_m,
                "Day(s)": count_d
            }
        if d1 > d2 or d1 == d2:
            count_y = y1 - y2
            count_m = m1 - m2
            count_d = d1 - d2
            return {
                "Year(s)": count_y,
                "Month(s)": count_m,
                "Day(s)": count_d
            }
    if m1 > m2:
        if d1 < d2:
            m1 -= 1
            d1 += 30 # imagine all months have 30 days
            count_y = y1 - y2
            count_m = m1 - m2
            count_d = d1 - d2
            return {
                "Year(s)": count_y,
                "Month(s)": count_m,
                "Day(s)": count_d
            }
        if d1 > d2 or d1 == d2:
            count_y = y1 - y2
            count_m = m1 - m2
            count_d = d1 - d2
            return {
                "Year(s)": count_y,
                "Month(s)": count_m,
                "Day(s)": count_d
            }

# list account that ever went dormant (has no transaction for 3 months straight). show account information and dormant period
@app.route('/account/dormant/', methods = ["GET"])
def get_dormant():
    login = authz()
    if check_user(login): #if false
        return jsonify({
            'error' : 'Bad Request',
            'message' : 'Username is not registered'
        }), 400
    else:
        if get_password(login): #if false
            return jsonify({
            'error' : 'Bad Request',
            'message' : 'Wrong Password'
        }), 400
        else: #if true
            if not get_is_admin(login): #if false
                return jsonify({
                'error' : 'Bad Request',
                'message' : 'You do not have the authority to do this operation'
                }), 400
            else: #if true
                data = request.get_json()
                if not "today's_date" in data:
                    return jsonify({
                                'error' : 'Bad Request',
                                'message' : "today's_date is not given"
                            }), 400
                else:
                    
                    date1 = data["today's_date"]
                    x = date1.split("-")
                    y, m, d = int(x[0]), int(x[1]), int(x[2])
                    if m < 4:
                        y -= 1
                        if m == 3:
                            m1 = 12
                        if m == 2:
                            m1 = 11
                        if m == 1:
                            m1 = 1
                        date2 = str(y)+"-"+str(m1)+"-"+str(d)
                        account = Account.query.filter_by(last_transaction < date2).all
                        return jsonify([
                            {
                                "Account Number": acc.account_number,
                                "Account Type": acc.account_type,
                                "Account Balance": acc.account_balance,
                                "Last Transaction": acc.last_transaction,
                                "Owner Name": acc.x.full_name,
                                "Dormant Period": get_dormant_period(data["today's_date"], acc.last_transaction)
                            } for acc in account
                        ])
                    if m > 3:
                        m -= 3
                        date3 = str(y)+"-"+str(m)+"-"+str(d)
                        account = Account.query.filter(Account.last_transaction < date3).all()
                        return jsonify([
                            {
                                "Account Number": acc.account_number,
                                "Account Type": acc.account_type,
                                "Account Balance": acc.account_balance,
                                "Last Transaction": acc.last_transaction,
                                "Owner Name": acc.x.full_name,
                                "Dormant Period": get_dormant_period(data["today's_date"], acc.last_transaction)
                            } for acc in account
                        ])
                    