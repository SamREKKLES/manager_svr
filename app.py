import os
from datetime import time
from auths import *
from flask import Flask, request, session
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import null
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import ValidationError, Length
from flask_wtf import CSRFProtect
import uuid
from common import successReturn, failReturn, SQLALCHEMY_DATABASE_URI

# todo 单点登陆 保证manager和model能够同时校验通过 或 在model添加自定义校验
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['WTF_CSRF_ENABLED'] = False
db = SQLAlchemy(app)

app.secret_key = os.urandom(24)

CSRFProtect(app)

# enable CORS
CORS(app, supports_credentials=True, resources={r'/*': {'origins': '*'}})


class CTImg(db.Model):
    __tablename__ = 'ctimgs'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), unique=True)
    uploadname = db.Column(db.String(255), unique=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    type = db.Column(db.String(255), unique=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'))
    patient = db.relationship('Patient', backref=db.backref('ctimgs', lazy='dynamic'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    docter = db.relationship('User', backref=db.backref('ctimgs', lazy='dynamic'))

    def __init__(self, filename, uploadname, img_type, patient, doctor):
        self.filename = filename
        self.type = img_type
        self.patient = patient
        self.uploadname = uploadname
        self.docter = doctor

    def __repr__(self):
        return '<DWI %r>' % self.filename


class Result(db.Model):
    __tablename__ = 'results'
    id = db.Column(db.Integer, primary_key=True)
    filename1 = db.Column(db.String(255), unique=True)
    filename2 = db.Column(db.String(255), unique=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    modeltype = db.Column(db.String(255), unique=True)
    dwi_name = db.Column(db.String(255), unique=False)
    adc_name = db.Column(db.String(255), unique=False)
    info = db.Column(db.String(255), unique=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'))
    patient = db.relationship('Patient', backref=db.backref('results', lazy='dynamic'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    docter = db.relationship('User', backref=db.backref('results', lazy='dynamic'))
    realimg = db.Column(db.String(255), unique=True)
    roi = db.Column(db.String(255), unique=True)

    def __init__(self, filename1, filename2, modeltype, patient, doctor, dwi_name, adc_name, info):
        self.filename1 = filename1
        self.filename2 = filename2
        self.modeltype = modeltype
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
    username = db.Column(db.String(255), unique=True)
    age = db.Column(db.Integer)
    sex = db.Column(db.Integer)
    info = db.Column(db.String(255))
    result = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.now)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    docter = db.relationship('User', backref=db.backref('patients', lazy='dynamic'))

    def __init__(self, username, doctor, age, sex, info, result):
        self.username = username
        self.docter = doctor
        self.age = age
        self.sex = sex
        self.info = info
        self.result = result

    def __repr__(self):
        return '<Patient %r>' % self.username


# User==Doctor
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    realname = db.Column(db.String(255), unique=False)
    userType = db.Column(db.Integer)

    def __init__(self, username, password, realname, userType=2):
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

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return '<User %r>' % self.username


# LoginForm 登陆表单
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[Length(max=64)])
    password = PasswordField('Password', validators=[Length(6, 16)])

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
    realname = StringField('Realname', validators=[Length(max=64)])

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).count() > 0:
            raise ValidationError('Username %s already exists!' % field.data)


db.create_all()

FILE_LIST = []


def _get_current_user():
    """
    获取当前用户
    :return:
    """
    currentName = session["user_name"]
    if currentName:
        return User.query.filter_by(username=currentName).first()
    return null


@app.route('/api/login', methods=['POST', "GET"])
@cross_origin()
def login():
    """
    用户登录
    :return: json
    """
    user_data = request.get_json()
    form = LoginForm(data=user_data)
    if form.validate_on_submit():
        user = form.get_user()
        access_token = generate_access_token(user_name=user.username)
        refresh_token = generate_refresh_token(user_name=user.username)
        data = {"access_token": access_token.decode("utf-8"),
                "refresh_token": refresh_token.decode("utf-8")}
        return successReturn(data, "登陆成功")
    return failReturn("", "用户名或密码错误")


@app.route('/api/register', methods=['POST'])
@cross_origin()
def register():
    """
    用户注册
    :return: json
    """
    user_data = request.get_json()
    form = RegisterForm(data=user_data)
    if form.validate():
        user = User(username=user_data['username'], password=user_data['password'], realname=user_data['realname'])
        db.session.add(user)
        db.session.commit()
        return successReturn("", "注册成功")
    return failReturn(form.errors, "注册失败")


@app.route('/api/refreshToken', methods=["GET"])
def refresh_token():
    """
    刷新token，获取新的数据获取token, 当前jwt过期后可请求refresh
    :return:
    """
    user_data = request.get_json()
    refresh_token = user_data['refresh_token']
    if not refresh_token:
        return failReturn("", "参数错误")
    payload = decode_auth_token(refresh_token)
    if not payload:
        return failReturn("", "请登陆")
    if "user_name" not in payload:
        return failReturn("", "请登陆")
    access_token = generate_access_token(user_name=payload["user_name"])
    data = {"access_token": access_token.decode("utf-8"), "refresh_token": refresh_token}
    return successReturn(data, "刷新成功")


@app.route("/api/logout", methods=['GET'])
@login_required
@cross_origin()
def logout():
    """
    用户退出, todo：目前把工作交给前端，可以考虑加一个黑名单记录已删除token！！！
    :return: json
    """
    session.clear()
    return successReturn("", "退出登陆")


def _get_username():
    """
    获取当前用户名和id
    :return: realname, id
    """
    doctor = _get_current_user()
    if doctor:
        return doctor.realname, doctor.id
    return False


@app.route('/api/getUser', methods=['GET'])
@login_required
@cross_origin()
def get_user():
    """
    获取用户信息
    :return: json
    """
    username, id = _get_username()
    if not username:
        return failReturn("", "获取信息失败")
    return successReturn({"username": username, "id": id}, '获取信息成功')


def _add_patient(name, sex, age, info, result):
    """
    添加病人
    :param name:
    :param sex:
    :param age:
    :param info:
    """
    doctor = _get_current_user()
    patient = Patient(name, doctor, age, sex, info, result)
    db.session.add(patient)
    db.session.commit()


def _get_patients():
    """
    获取病人列表
    :return: patients
    """
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
    """
    通过id获取病人
    :param id:
    :return: patient
    """
    def to_dict(p):
        return {'id': p.id, "name": p.username, "sex": "男" if p.sex == 1 else "女", "info": p.info, "age": p.age}

    patient = Patient.query.filter_by(id=id).first()
    doctor = _get_current_user()
    if doctor.userType == 1 or patient.docter == doctor:
        return to_dict(patient)
    else:
        return None


def _del_patient(id):
    """
    删除病人
    :param id:
    :return: boolean
    """
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


@app.route('/api/addPatient', methods=['POST'])
@login_required
@cross_origin()
def add_patient():
    """
    添加病人
    :return: json
    """
    json = request.get_json()
    name = json['name']
    sex = json['sex']
    age = json['age']
    info = json['desc']
    result = json['result']
    _add_patient(name, sex, age, info, result)
    return successReturn("", "成功添加病人")


@app.route('/api/getPatients', methods=['GET'])
@login_required
@cross_origin()
def get_patients():
    """
    获取病人列表
    :return: json
    """
    patients = _get_patients()
    response_object = {'patients': patients}
    return successReturn(response_object, "获取病人列表成功")


@app.route('/api/getPatient', methods=['POST'])
@login_required
@cross_origin()
def get_patient():
    """
    根据id获取病人
    :return: json
    """
    json = request.get_json()
    id = json['id']
    patient = _get_patient(id)
    if not patient:
        return failReturn("", "获取病人失败")
    response_object = {'patient': patient}
    return successReturn(response_object, "获取病人成功")


@app.route('/api/delPatient', methods=['POST'])
@login_required
@cross_origin()
def del_patient():
    """
    删除病人
    :return: json
    """
    patient = request.get_json()['patient']
    if not _del_patient(patient):
        return failReturn("", "删除失败")
    return successReturn("", "删除成功")


def _get_img_list(id):
    """
    获取imgList
    :param id:
    :return: res
    """
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


@app.route('/api/getDetail', methods=['POST'])
@login_required
@cross_origin()
def get_detail():
    """
    获取病人详细信息
    :return: json
    """
    json = request.get_json()
    id = json['id']
    patient = _get_patient(id)
    if not patient:
        return failReturn("", "获取病人信息失败")
    img_list = _get_img_list(id)
    response_object = {'patient': patient, 'imgs': img_list}
    return successReturn(response_object, "获取病人信息成功")


@app.route('/api/imgList', methods=['POST'])
@login_required
@cross_origin()
def get_img_list():
    """
    获取图像信息
    :return: json
    """
    patient = request.get_json()['patient']
    if not patient:
        return failReturn("", "获取图像列表失败")
    img_list = _get_img_list(patient)
    response_object = {'imgs': img_list}
    return successReturn(response_object, "获取图像列表成功")


def _update_desc(id, info):
    """
    更新信息
    :param id:
    :param info:
    :return: boolean
    """
    patient = Patient.query.filter_by(id=id).first()
    if not patient:
        return False
    patient.info = info
    db.session.commit()
    return True


@app.route('/api/updateDesc', methods=['POST'])
@login_required
@cross_origin()
def update_desc():
    """
    更新用户信息
    :return: json
    """
    json = request.get_json()
    id = json['id']
    info = json['desc']
    if not _update_desc(id, info):
        return failReturn("", "更新失败")
    return successReturn("", "更新成功")


def _statistics():
    """
    获取医生信息，根据当前权限
    :return: res
    """
    doctor = _get_current_user()
    if doctor.userType != 1:
        return None
    users = User.query.all()
    res = []
    for u in users:
        res.append({"id": u.id, "name": u.realname, "patients": u.patients.count(), "res": u.results.count(),
                    "role": "医生" if u.userType == 2 else "主任医生"})
    return res


@app.route('/api/statistics', methods=['GET'])
@login_required
@cross_origin()
def statistics():
    """
    获取用户列表
    :return: json
    """
    res = _statistics()
    if not res:
        return failReturn("", "权限不足")
    response_object = {'res': res}
    return successReturn(response_object, "获取用户列表成功")


@app.route('/api/userDetail', methods=['POST'])
@login_required
@cross_origin()
def user_detail():
    """
    获取用户详细信息
    :return: json
    """
    id = request.get_json()['id']
    user = User.query.filter_by(id=id).first()
    if not user:
        return failReturn("", "用户不存在")
    response_object = {'name': user.username, 'realname': user.realname, 'role': str(user.userType)}
    return successReturn(response_object, "获取用户详细信息成功")


@app.route('/api/updateRole', methods=['POST'])
@login_required
@cross_origin()
def update_role():
    """
    更新用户权限
    :return: json
    """
    doctor = _get_current_user()
    if doctor.userType != 1:
        return failReturn("", "权限不足")
    id = request.get_json()['id']
    role = request.get_json()['role']
    user = User.query.filter_by(id=id).first()
    if not user:
        return failReturn("", "用户不存在")
    user.userType = int(role)
    db.session.commit()
    return successReturn("", "更新权限成功")


@app.route('/api/series', methods=['GET'])
@cross_origin()
def series():
    """
    生成随机uuid
    :return:
    """
    node = uuid.getnode()
    mac = uuid.UUID(int=node).hex[-12:]
    response_object = {'mac': mac}
    return successReturn(response_object, "生成随机uuid")


if __name__ == '__main__':
    def after_request(resp):
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        return resp


    app.after_request(after_request)
    app.run(debug=True, threaded=True, host='127.0.0.1', port=5050)
