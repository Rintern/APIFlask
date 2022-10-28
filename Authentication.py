from unicodedata import name
from flask import Flask, request, jsonify, make_response
import jwt
from flask_sqlalchemy import SQLAlchemy
import uuid
from itsdangerous import json
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from functools import wraps

app= Flask(__name__)

app.config["SECRET_KEY"]="thisisthesecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

class User(db.Model):
    id= db.Column(db.Integer, primary_key= True)
    public_id= db.Column(db.String(50), unique=True)
    name=db.Column(db.String(100))
    password=db.Column(db.String(50))
    admin= db.Column(db.Boolean)

    
db.create_all()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token= request.headers['x-access-token']
        # if not token:
        #     return({'message':'Token is missing'}), 401
        
        try:
            data= jwt.decode(token, app.config['SECRET_KEY'])
            
            current_user= User.query.filter_by(public_id= data['public_id']).first()
        except:
            return jsonify({'message':"Token is invalid "}), 401
        
        return f(current_user,*args, **kwargs)
    return decorated
    

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    
    if not current_user.admin():
         return jsonify({"message":"Cannot perform this function"})
    
    users= User.query.all()
    
    output=[]
    
    for user in users:
        user_data= {}
        user_data['public_id']= user.public_id
        user_data['name']= user.name
        user_data['password']= user.password
        user_data['admin']= user.admin
        output.append(user_data)
    return jsonify({'users': output})
#@token_required

@app.route('/user/<public_id>', methods=['GET'])
def get_one_user(public_id):
    
    # if not current_user.admin():
    #     return jsonify({"message":"Cannot perform this function"})
    
    user= User.query.filter_by(public_id=public_id).first()
    
    if not user:
        return jsonify({"message":"No user with that ID found"})
    
    user_data={}
    user_data['public_id']= user.public_id
    user_data['name']= user.name
    user_data['password']= user.password
    user_data['admin']=user.admin
    
    return jsonify({"User": user_data})
#@token_required
  

@app.route('/user', methods=['POST'])

def add_user():
    
    # if not current_user.admin():
    #     return jsonify({"message":"Cannot perform this function"})
    
    data= request.get_json()
    hashed_pw= generate_password_hash(data['password'], method='sha256')
    new_user=User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_pw, admin=False)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'New user is created'})
#@token_required

@app.route('/user/<public_id>', methods=['PUT'])

def update_user(public_id):
    
    # if not current_user.admin():
    #     return jsonify({"message":"Cannot perform this function"})
    
    user= User.query.filter_by(public_id= public_id).first()
    
    if not user:
        return jsonify({"message":"No user with that ID found"})
    
    user.admin = True
    db.session.commit()
    
    return jsonify({"message":"User status updated to admin"})
#@token_required

@app.route('/user/<public_id>', methods=['DELETE'])

def delete_user( public_id):
    
    # if not current_user.admin():
    #     return jsonify({"message":"Cannot perform this function"})
    
    user= User.query.filter_by(public_id= public_id).first()
    
    if not user:
        return jsonify({"message":"No user with that ID found"})
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({"message": "User has been deleted"})
#@token_required

@app.route('/login')
def login():
    auth=request.authorization
    
    if not auth or not auth.username or not auth.password:
        return make_response("Could not verify", 401, {'WWW_Authenticate': 'Basic realm = Login Required'})
    
    user= User.query.filter_by(name= auth.username).first()
    
    if not user:
        return make_response("Could not verify", 401, {'WWW_Authenticate': 'Basic realm = Login Required'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        
        return jsonify({'token' : token})
    
    return make_response("Could not verify", 401, {'WWW_Authenticate': 'Basic realm = Login Required'})


if __name__ == '__main__':
    app.run(debug=True)