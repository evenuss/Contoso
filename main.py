from app import *
from flask_pymongo import pymongo

@app.route('/register', methods=['POST'])
def CreateUser():
    if request.form:
        GenerateUserId = uuid.uuid4()
        UserId = GenerateUserId
        print(request.form)
        password = request.form['password']
        pw_hash = bcrypt.generate_password_hash(password)
        email = request.form['email']
        existing_user = mongo.db.user.find_one({"email": email})
        fullName = request.form['fullName']
        address = request.form['address']
        phoneNumber = request.form['phoneNumber']
        role = "member"
        verified = "No"
        # profilePictureUrl = request.form['profilePictureUrl']
        createdAt = datetime.now()
        updatedAt = datetime.now()
    else:
        GenerateUserId = uuid.uuid4()
        UserId = GenerateUserId
        print(request.get_json())
        password = request.json['password']
        pw_hash = bcrypt.generate_password_hash(password)
        email = request.json['email']
        existing_user = mongo.db.user.find_one({"email": email})
        fullName = request.json['fullName']
        address = request.json['address']
        phoneNumber = request.json['phoneNumber']
        role = "member"
        verified = "No"
        # profilePictureUrl = request.json['profilePictureUrl']
        createdAt = datetime.now()
        updatedAt = datetime.now()

    if existing_user is None:
        mongo.db.user.insert({'UserId': UserId ,'fullName': fullName,'email': email, 'password': pw_hash,'address':address,'phoneNumber':phoneNumber,'role':role,'verified':verified,'profilePictureUrl':'-','createdAt':createdAt,'updatedAt':updatedAt})
        return jsonify({'message':'Registrasi berhasil !'})

    return jsonify({'message':'Email already exists'})

# Tambah Fitur Login
@app.route('/login', methods=['POST'])
def login():
    if request.form:
        data = request.form
        email = data['email']
        pw_hash = bcrypt.generate_password_hash(data['password'])
        a = mongo.db.user.find_one({'email':email})
        b = bcrypt.check_password_hash(a['password'],data['password'])
        result =[]
    else:
        data = request.json
        email = data['email']
        pw_hash = bcrypt.generate_password_hash(data['password'])
        a = mongo.db.user.find_one({'email': email})
        b = bcrypt.check_password_hash(a['password'], data['password'])
        result = []
    if b == True:
        isi = mongo.db.user.find({'email':email})
        for doc in isi:
            result.append({
                'UserId':str(doc['UserId']),
                'fullName':doc['fullName'],
                'role':doc['role'],
                'verified':doc['verified']
            })
        expires = dt.timedelta(days=1)
        access_token = create_access_token(identity=email,expires_delta=expires)
        return jsonify({
            'result':result,
            'access_token':access_token,
            'status': 200
        })
    else:
        return jsonify({
            'result':'Not Found',
            'status':404

        })

@app.route('/edit', methods=['PUT'])
@jwt_required
def editData():
    if request.form:
        fullName = request.form['fullName']
        address = request.form['address']
        phoneNumber = request.form['phoneNumber']
        profilePictureUrl = request.form['profilePictureUrl']
        email = request.form['email']
    else:
        fullName = request.json['fullName']
        address = request.json['address']
        phoneNumber = request.json['phoneNumber']
        profilePictureUrl = request.json['profilePictureUrl']
        email = request.json['email']

    updatequery = {'email': email}
    newvalues = {'$set': {'fullName': fullName, 'address': address, 'phoneNumber': phoneNumber,
                                  'profilePictureUrl': profilePictureUrl}}
    mongo.db.user.update_one(updatequery, newvalues)
    return jsonify({'message': 'Edit berhasil'})

@app.route('/forgetpassword', methods=['POST'])
def SendEmailForgetPassword():
    if request.form:
        email = request.form['email']
    else:
        email= request.json['email']

    access_token = create_access_token(identity=email)

    msg = Message("EMAIL CONFIRMATION",
                  sender='EMAIL_VERIFICATION',
                  recipients=[email])
    msg.html = render_template('emails/email-verification.html')
    mail.send(msg)
    return jsonify({'message':'Buka email anda','access_token':access_token})

@app.route('/forgetpassword/changepassword',methods=['PUT'])
@jwt_required
def updateForgetPassword():
    email = get_jwt_identity()
    if request.form:
        newpassword = request.form['newpassword']
    else:
        newpassword = request.json['newpassword']
    pw_hash = bcrypt.generate_password_hash(newpassword)
    print(email)
    updatequery = {'email': email}
    newvalues = {'$set': {'password': pw_hash}}
    mongo.db.user.update_one(updatequery, newvalues)

    return jsonify({'message':'success'})

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist



@app.route('/logout', methods=['DELETE'])
@jwt_required
def logout():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out"}), 200



@app.route('/logout2', methods=['DELETE'])
@jwt_required
def logout2():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out"}), 200


@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    return jsonify({'hello': 'world'})


#######################################################################################################################

@app.route('/createtask', methods=['POST'])
@jwt_required
def newTask():
    if request.form:
        GenerateToDoId = uuid.uuid4()
        name = request.form['name']
        try:
            description = request.form['description']
        except:
            description = None
        date = request.form['date']
        favorite = False
        completed = False
        deleted = False
        userId = request.form['userId']
        createdAt = datetime.now()
        updatedAt = datetime.now()
    else:
        GenerateToDoId = uuid.uuid4()
        name = request.json['name']
        try:
            description = request.json['description']
        except:
            description = None
        date = request.json['date']
        favorite = False
        completed = False
        deleted = False
        userId = request.json['userId']
        createdAt = datetime.now()
        updatedAt = datetime.now()
    try:
        new_task = mongo.db.todo.insert(
                {
                    "toDoId":GenerateToDoId,
                    "name":name,
                    "description":description,
                    "date":date,
                    "favorite":favorite,
                    "completed":completed,
                    "deleted":deleted,
                    "userId":userId,
                    "createdAt":createdAt,
                    "updatedAt":updatedAt
                })
        if new_task and request.method == 'POST':
            return jsonify('Success!')
    except Exception as e:
        return e

@app.route('/showall', methods=['POST','GET'])
@jwt_required
def showalltodolist():
    if request.form:
        user_id = request.form['user_id']
    else:
        user_id = request.json['user_id']
    todolist = mongo.db.todo.find({'userId': user_id,'deleted':False})
    result = []
    for alltodo in todolist:
        result.append({
            'toDoId':str(alltodo['toDoId']),
            'name':alltodo['name'],
            'description':alltodo['description'],
            'date':alltodo['date'],
            'favorite': alltodo['favorite'],
            'completed': alltodo['completed'],
            'deleted': alltodo['deleted'],
            'createdAt': alltodo['createdAt'],
            'updatedAt': alltodo['updatedAt'],
        })
    resp = jsonify({'result':result})
    return resp

@app.route('/delete', methods=['PUT'])
def delete():
    tododelete = ["dandung","arjuna","arya"]
    for bulkdelete in tododelete:
        updatequery = {'name': bulkdelete}
        newvalues = {'$set': {'deleted': False}}
        mongo.db.todo.update_one(updatequery, newvalues)
    return jsonify({'message':'success','status':200})




@app.route('/todolist/page', methods = ['GET'])
@jwt_required
def pagination():
    if request.form:
        user_id = request.form['user_id']
    else:
        user_id = request.json['user_id']
    number = mongo.db.todo

    offset = int(request.args['offset'])
    limit = int(request.args['limit'])

    starting_id = number.find({'userId': user_id,'deleted':False}).sort('_id', pymongo.ASCENDING)
    last_id= starting_id[offset]['_id']

    pagination = number.find({'_id' : {'$gte': last_id}}).sort('_id', pymongo.ASCENDING).limit(limit)
    output = []

    for i in pagination:
        output.append({'name': i['name'],'description': i['description'],'date': i['date'],'favorite': i['favorite'],'deleted': i['deleted'],'createdAt': i['createdAt'],'updatedAt': i['updatedAt']})

    if offset == 0 :
        next_url = '/todolist/page?limit=' + str(limit) + '&offset=' + str(offset + limit)
        prev_url = ''
    else:
        next_url = '/todolist/page?limit=' + str(limit) + '&offset=' + str(offset + limit)
        prev_url = '/todolist/page?limit=' + str(limit) + '&offset=' + str(offset - limit)

    return jsonify({'result': output,'prev_url': prev_url ,'next_url': next_url})


@app.route('/uploader', methods = ['GET', 'POST'])
def upload_fille():
   if request.method == 'POST':
      f = request.files['file']
      f.save(secure_filename(f.filename))
      return 'file uploaded successfully'


@app.route('/upload',methods = ['GET','POST'])
def upload_file():
    if request.method =='POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
            mongo.db.image.insert({'url':filename})
            return "sucess"
    return "Sucess!"


if __name__ == "__main__":
    app.run(debug=True)