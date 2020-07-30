import os
from datetime import time

from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, logout_user, login_required, LoginManager, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import ValidationError, Length
from flask_wtf import CSRFProtect
import uuid

# todo 单点登陆 保证manager和model能够同时校验通过 或 在model添加自定义校验

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///manager.db' + '?check_same_thread=False'  # todo 待修改
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['WTF_CSRF_ENABLED'] = False
db = SQLAlchemy(app)

app.secret_key = os.urandom(24)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.init_app(app=app)

CSRFProtect(app)

# enable CORS
CORS(app, supports_credentials=True, resources={r'/*': {'origins': '*'}})


class CTImg(db.Model):
    __tablename__ = 'ctimgs'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), unique=True)
    uploadname = db.Column(db.String(120), unique=False)
    time = db.Column(db.String(10), unique=False)
    type = db.Column(db.String(10), unique=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'))
    patient = db.relationship('Patient', backref=db.backref('ctimgs', lazy='dynamic'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    docter = db.relationship('User', backref=db.backref('ctimgs', lazy='dynamic'))

    def __init__(self, filename, uploadname, img_type, patient, doctor, cttime=None):
        self.filename = filename
        if cttime is None:
            cttime = time.time()
        self.time = cttime
        self.type = img_type
        self.patient = patient
        self.uploadname = uploadname
        self.docter = doctor

    def __repr__(self):
        return '<DWI %r>' % self.filename


class Result(db.Model):
    __tablename__ = 'results'
    id = db.Column(db.Integer, primary_key=True)
    filename1 = db.Column(db.String(120), unique=True)
    filename2 = db.Column(db.String(120), unique=True)
    time = db.Column(db.String(10), unique=False)
    modelType = db.Column(db.Integer)
    dwi_name = db.Column(db.String(120), unique=False)
    adc_name = db.Column(db.String(120), unique=False)
    info = db.Column(db.Float, unique=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'))
    patient = db.relationship('Patient', backref=db.backref('results', lazy='dynamic'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    docter = db.relationship('User', backref=db.backref('results', lazy='dynamic'))
    realimg = db.Column(db.String(120), unique=True)
    roi = db.Column(db.String(120), unique=True)

    def __init__(self, filename1, filename2, modelType, patient, doctor, dwi_name, adc_name, info, cttime=None):
        self.filename1 = filename1
        self.filename2 = filename2
        if cttime is None:
            cttime = time.time()
        self.time = cttime
        self.modelType = modelType
        self.patient = patient
        self.docter = doctor
        self.dwi_name = dwi_name
        self.adc_name = adc_name
        self.info = info

    def __repr__(self):
        return '<DWI %r>' % self.filename


class Patient(db.Model):
    __tablename__ = 'patients'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    age = db.Column(db.Integer)
    sex = db.Column(db.Integer)
    info = db.Column(db.String)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    docter = db.relationship('User', backref=db.backref('patients', lazy='dynamic'))

    def __init__(self, username, doctor, age, sex, info):
        self.username = username
        self.docter = doctor
        self.age = age
        self.sex = sex
        self.info = info

    def __repr__(self):
        return '<Patient %r>' % self.username


# User==Doctor
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    password = db.Column(db.String(200))
    realname = db.Column(db.String(128), unique=False)
    userType = db.Column(db.Integer)

    def __init__(self, username, password, realname, userType=1):
        password = generate_password_hash(password)
        self.username = username
        self.password = password
        self.realname = realname
        self.userType = userType

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def to_json(self):
        return {'id': self.id, 'username': self.username,
                'realname': self.realname, 'usertype': self.userType}

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return '<User %r>' % (self.username)


# LoginForm 登陆表单
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[Length(max=64)])
    password = PasswordField('Password', validators=[Length(6, 16)])
    remember = BooleanField('Remember Me')

    def validate_username(self, field):
        if not self.get_user():
            raise ValidationError('Invalid username!')

    def validate_password(self, field):
        if not self.get_user():
            return
        if not self.get_user().check_password(field.data):
            raise ValidationError('Incorrect password!')

    def get_user(self):
        return User.query.filter_by(username=self.username.data).first()


# RegisterForm 注册表单
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[Length(max=64)])
    password = PasswordField('Password', validators=[Length(1, 16)])
    confirm = PasswordField('Confirm Password')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).count() > 0:
            raise ValidationError('Username %s already exists!' % field.data)


db.create_all()

FILE_LIST = []


# load_user 加载当前登陆用户验证
@login_manager.user_loader
def load_user(userid):
    return User.query.get(int(userid))


def _get_current_user():
    return load_user(current_user.id)


# login 用户登录
@app.route('/api/login', methods=['POST', 'GET'])
@cross_origin()
def login():
    if current_user.is_authenticated:
        return jsonify({'status': 'success'})
    user_data = request.get_json()
    form = LoginForm(data=user_data)
    if form.validate_on_submit():
        user = form.get_user()
        login_user(user, remember=True)
        return jsonify({'status': 'success', 'user': user.to_json()})
    return jsonify({'status': 'fail'})


# register 注册用户
@app.route('/api/register', methods=['POST'])
@cross_origin()
def register():
    user_data = request.get_json()
    form = RegisterForm(data=user_data)
    if form.validate():
        user = User(username=user_data['username'], password=user_data['password'],
                    realname=user_data['realname'], userType=user_data['userType'])
        db.session.add(user)
        db.session.commit()
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': form.errors}), 400


# logout 退出登录
@app.route("/api/logout", methods=['GET'])
@login_required
@cross_origin()
def logout():
    logout_user()
    return jsonify({'status': 'success'})


def _get_username():
    doctor = _get_current_user()
    if doctor:
        return doctor.realname, doctor.id
    return False


# getUser 获取当前用户
@app.route('/api/getUser', methods=['GET'])
@login_required
@cross_origin()
def get_user():
    response_object = {'status': 'success'}
    username, id = _get_username()
    if not username:
        response_object['status'] = 'fail'
    else:
        response_object['username'] = username
        response_object['id'] = id
    return jsonify(response_object)


def _add_patient(name, sex, age, info):
    doctor = _get_current_user()
    patient = Patient(name, doctor, age, sex, info)
    db.session.add(patient)
    db.session.commit()


def _get_patients():
    def to_dict(patients):
        res = []
        for p in patients:
            res.append({'id': p[0], "name": p[1], "sex": "男" if p[2] == 1 else "女", "info": p[4], "age": p[3]})
        return res

    def to_dict1(patients):
        res = []
        for p in patients:
            res.append(
                {'id': p.id, "name": p.username, "sex": "男" if p.sex == 1 else "女", "info": p.info, "age": p.age})
        return res

    doctor = _get_current_user()
    if doctor.userType == 1:
        patients = db.session.query(Patient.id, Patient.username, Patient.sex, Patient.age, Patient.info).all()
        return to_dict(patients)
    else:
        patients = doctor.patients.all()
        return to_dict1(patients)


def _get_patient(id):
    def to_dict(p):
        return {'id': p.id, "name": p.username, "sex": "男" if p.sex == 1 else "女", "info": p.info, "age": p.age}

    patient = Patient.query.filter_by(id=id).first()
    doctor = _get_current_user()
    if doctor.userType == 1 or patient.docter == doctor:
        return to_dict(patient)
    else:
        return None


def _del_patient(id):
    user = Patient.query.filter_by(id=id).first()
    if not user:
        return False
    img_list = Patient.query.filter_by(id=id).first().ctimgs.all()
    db.session.delete(user)
    if img_list:
        for item in img_list:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], item.filename))
            db.session.delete(item)
    db.session.commit()
    return True


# addPatient 添加病人
@app.route('/api/addPatient', methods=['POST'])
@login_required
@cross_origin()
def add_patient():
    response_object = {'status': 'success'}
    json = request.get_json()
    name = json['name']
    sex = json['sex']
    age = json['age']
    info = json['desc']
    _add_patient(name, sex, age, info)
    return jsonify(response_object)


# getPatients 获取病人列表
@app.route('/api/getPatients', methods=['GET'])
@login_required
@cross_origin()
def get_patients():
    patients = _get_patients()
    response_object = {'status': 'success', 'patients': patients}
    return jsonify(response_object)


# getPatient 根据id获取病人
@app.route('/api/getPatient', methods=['POST'])
@login_required
@cross_origin()
def get_patient():
    response_object = {'status': 'success'}
    json = request.get_json()
    id = json['id']
    patient = _get_patient(id)
    if patient:
        response_object['patient'] = patient
    else:
        response_object['status'] = "fail"
    return jsonify(response_object)


# delPatient 删除病人
@app.route('/api/delPatient', methods=['POST'])
@login_required
@cross_origin()
def del_patient():
    response_object = {'status': 'success'}
    patient = request.get_json()['patient']
    if not _del_patient(patient):
        response_object['status'] = 'fail'
    return jsonify(response_object)


# _get_img_list 获取imgList
def _get_img_list(id):
    res = []
    img_list = Patient.query.filter_by(id=id).first().ctimgs.order_by("time").all()
    for item in img_list:
        res.append(
            {
                "uploadname": item.uploadname,
                "time": time.strftime("%Y%m%d", time.localtime(int(item.time))),
                "type": item.type,
                "filename": item.filename,
                "disabled": False
            }
        )
    return res


# get_detail 获取病人信息
@app.route('/api/getDetail', methods=['POST'])
@login_required
@cross_origin()
def get_detail():
    response_object = {'status': 'success'}
    json = request.get_json()
    id = json['id']
    patient = _get_patient(id)
    if patient:
        response_object['patient'] = patient
    else:
        response_object['status'] = "fail"
        return jsonify(response_object)
    img_list = _get_img_list(id)
    response_object['imgs'] = img_list
    return jsonify(response_object)


# get_img_list 获取图像信息
@app.route('/api/imgList', methods=['POST'])
@login_required
@cross_origin()
def get_img_list():
    response_object = {'status': 'success'}
    patient = request.get_json()['patient']
    if not patient:
        return response_object
    img_list = _get_img_list(patient)
    response_object['imgs'] = img_list
    return jsonify(response_object)

# _update_desc 更新信息
def _update_desc(id, info):
    patient = Patient.query.filter_by(id=id).first()
    if not patient:
        return False
    patient.info = info
    db.session.commit()
    return True


# updateDesc 更新用户信息
@app.route('/api/updateDesc', methods=['POST'])
@login_required
@cross_origin()
def update_desc():
    response_object = {'status': 'success'}
    json = request.get_json()
    id = json['id']
    info = json['desc']
    if not _update_desc(id, info):
        response_object['status'] = 'fail'
    return jsonify(response_object)


def _statistics():
    doctor = _get_current_user()
    if doctor.userType != 1:
        return None
    users = User.query.all()
    res = []
    for u in users:
        res.append({"id": u.id, "name": u.realname, "patients": u.patients.count(), "res": u.results.count(),
                    "role": "医生" if u.userType == 2 else "主任医生"})
    return res


# statistics 获取用户列表
@app.route('/api/statistics', methods=['GET'])
@login_required
@cross_origin()
def statistics():
    response_object = {'status': 'success'}
    res = _statistics()
    if not res:
        response_object['status'] = 'fail'
    response_object['res'] = res
    return jsonify(response_object)


# userDetail 用户详细信息 todo 接口有更改
@app.route('/api/userDetail', methods=['POST'])
@login_required
@cross_origin()
def user_detail():
    response_object = {'status': 'success'}
    id = request.get_json()['id']
    user = User.query.filter_by(id=id).first()
    if not user:
        response_object['status'] = 'fail'
        return jsonify(response_object)
    response_object['name'] = user.username
    response_object['realname'] = user.realname
    response_object['role'] = str(user.userType)
    return jsonify(response_object)


# updateRole 更新用户权限
@app.route('/api/updateRole', methods=['POST'])
@login_required
@cross_origin()
def update_role():
    response_object = {'status': 'success'}
    doctor = _get_current_user()
    if doctor.userType != 1:
        response_object['status'] = 'fail'
        return jsonify(response_object)
    id = request.get_json()['id']
    role = request.get_json()['role']
    user = User.query.filter_by(id=id).first()
    if not user:
        response_object['status'] = 'fail'
        return jsonify(response_object)
    user.userType = int(role)
    db.session.commit()
    return jsonify(response_object)


# series 生成随机uuid
@app.route('/api/series', methods=['GET'])
@cross_origin()
def series():
    response_object = {'status': 'success'}
    node = uuid.getnode()
    mac = uuid.UUID(int=node).hex[-12:]
    response_object['mac'] = mac
    return jsonify(response_object)


if __name__ == '__main__':
    def after_request(resp):
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        return resp


    app.after_request(after_request)
    app.run(debug=True, threaded=True, host='0.0.0.0', port=5050)
