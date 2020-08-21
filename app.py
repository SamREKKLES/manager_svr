import os

from flasgger import Swagger

from utils import common
from utils.auths import *
from flask import Flask, request, session
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import null, func
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import ValidationError, Length
from flask_wtf import CSRFProtect
from utils.common import successReturn, failReturn, SQLALCHEMY_DATABASE_URI

# todo 单点登陆 保证manager和model能够同时校验通过 或 在model添加自定义校验
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['WTF_CSRF_ENABLED'] = False
swagger_config = Swagger.DEFAULT_CONFIG
swagger_config['title'] = common.SWAGGER_TITLE
swagger_config['description'] = common.SWAGGER_DESC
Swagger(app, config=swagger_config)
db = SQLAlchemy(app)

app.secret_key = os.urandom(24)

CSRFProtect(app)

# enable CORS
CORS(app, supports_credentials=True, resources={r'/*': {'origins': '*'}})


class Img(db.Model):
    __tablename__ = 'imgs'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), unique=True)
    uploadname = db.Column(db.String(255), unique=False)
    timestamp = db.Column(db.DateTime)
    type = db.Column(db.String(255), unique=False)
    patient_id = db.Column(db.Integer)
    doctor_id = db.Column(db.Integer)

    def __init__(self, filename, uploadname, img_type, patient, doctor):
        self.filename = filename
        self.type = img_type
        self.patient_id = patient
        self.uploadname = uploadname
        self.doctor_id = doctor
        self.timestamp = datetime.now()

    def __repr__(self):
        return '<DWI %r>' % self.filename


class Result(db.Model):
    __tablename__ = 'results'
    id = db.Column(db.Integer, primary_key=True)
    filename1 = db.Column(db.String(255), unique=True)
    filename2 = db.Column(db.String(255), unique=True)
    timestamp = db.Column(db.DateTime)
    modeltype = db.Column(db.String(255), unique=True)
    dwi_name = db.Column(db.String(255), unique=False)
    adc_name = db.Column(db.String(255), unique=False)
    info = db.Column(db.Float, unique=False)
    patient_id = db.Column(db.Integer)
    doctor_id = db.Column(db.Integer)
    realimg = db.Column(db.String(255), unique=True)
    roi = db.Column(db.String(255), unique=True)

    def __init__(self, filename1, filename2, modeltype, patient, doctor, dwi_name, adc_name, info):
        self.filename1 = filename1
        self.filename2 = filename2
        self.modeltype = modeltype
        self.patient_id = patient
        self.doctor_id = doctor
        self.dwi_name = dwi_name
        self.adc_name = adc_name
        self.info = info
        self.timestamp = datetime.now()

    def __repr__(self):
        return '<DWI %r>' % self.filename


class Patient(db.Model):
    __tablename__ = 'patients'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    age = db.Column(db.Integer)
    sex = db.Column(db.Integer)
    record_id = db.Column(db.String(255))
    info = db.Column(db.String(255))
    result = db.Column(db.String(255))
    cva = db.Column(db.String(255))
    state = db.Column(db.String(255))
    create_time = db.Column(db.DateTime)
    update_time = db.Column(db.DateTime)
    doctor_id = db.Column(db.Integer)

    def __init__(self, username, recordID, state, doctor, age, sex, info, result, cva):
        self.username = username
        self.doctor_id = doctor
        self.record_id = recordID
        self.state = state
        self.age = age
        self.sex = sex
        self.info = info
        self.result = result
        self.cva = cva
        self.create_time = datetime.now()
        self.update_time = self.create_time

    def __repr__(self):
        return '<Patient %r>' % self.username


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    realname = db.Column(db.String(255), unique=False)
    userType = db.Column(db.Integer)

    def __init__(self, username, password, realname, userType=3):
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
    currentID = session["user_id"]
    if currentID:
        return User.query.filter_by(id=currentID).first()
    return null


@app.route('/api/login', methods=['POST'])
@cross_origin()
def login():
    """
    用户登录
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: 用户登录
          required:
            - username
            - password
          properties:
            username:
              type: string
              description: 用户名
            password:
              type: string
              description: 密码
    responses:
      fail:
        description: 用户名或密码错误
      success:
        description: 登陆成功
    """
    try:
        user_data = request.get_json()
        form = LoginForm(data=user_data)
        if form.validate_on_submit():
            user = form.get_user()
            access_token = generate_access_token(user_id=user.id)
            refreshToken = generate_refresh_token(user_id=user.id)
            data = {"access_token": access_token.decode("utf-8"),
                    "refresh_token": refreshToken.decode("utf-8")}
            return successReturn(data, "login: 登陆成功")
        return failReturn("", "login: 用户名或密码错误")
    except Exception as e:
        return failReturn(format(e), "login出错")


@app.route('/api/register', methods=['POST'])
@cross_origin()
def register():
    """
    用户注册
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: 用户注册
          required:
            - username
            - password
            - realname
          properties:
            username:
              type: string
              description: 用户名
            password:
              type: string
              description: 密码
            realname:
              type: string
              description: 真实姓名
    responses:
      fail:
        description: 注册失败
      success:
        description: 注册成功
    """
    try:
        user_data = request.get_json()
        form = RegisterForm(data=user_data)
        if form.validate():
            user = User(username=user_data['username'], password=user_data['password'], realname=user_data['realname'])
            db.session.add(user)
            db.session.commit()
            return successReturn("", "register: 注册成功")
        return failReturn(form.errors, "register: 注册失败")
    except Exception as e:
        return failReturn(format(e), "register出错")


@app.route('/api/refreshToken', methods=["POST"])
def refresh_token():
    """
    刷新token，获取新的数据获取token, 当前jwt过期后可请求refresh
    :return:
    ---
    tags:
      - Manager API
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: 刷新token
          required:
            - refresh_token
          properties:
            refresh_token:
              type: string
              description: refresh_token
    responses:
      fail:
        description: 注册失败
      success:
        description: 注册成功
    """
    try:
        user_data = request.get_json()
        refreshToken = user_data['refresh_token']
        if not refreshToken:
            return failReturn("", "refreshToken: 参数错误")
        payload = decode_auth_token(refreshToken)
        if not payload:
            return failReturn("", "refreshToken: 请登陆")
        if "user_id" not in payload:
            return failReturn("", "refreshToken: 请登陆")
        access_token = generate_access_token(user_id=payload["user_id"])
        data = {"access_token": access_token.decode("utf-8"), "refresh_token": refreshToken}
        return successReturn(data, "refreshToken: 刷新成功")
    except Exception as e:
        return failReturn(format(e), "refreshToken出错")


@app.route("/api/logout", methods=['GET'])
@login_required
@cross_origin()
def logout():
    """
    用户退出, todo：目前把工作交给前端，可以考虑加一个黑名单记录已删除token！！！
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
        description: token
    responses:
      success:
        description: 退出登陆
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
        return doctor.realname, doctor.id, doctor.userType
    return False


@app.route('/api/getUser', methods=['GET'])
@login_required
@cross_origin()
def get_user():
    """
    个人信息页
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
        description: token
    responses:
      fail:
        description: 注册失败
      success:
        description: 注册成功
    """
    try:
        username, id, userType = _get_username()
        if not username:
            return failReturn("", "getUser: 获取信息失败")
        return successReturn({"username": username, "id": id, "userType": userType}, "getUser: 获取信息成功")
    except Exception as e:
        return failReturn(format(e), "getUser出错")


def to_dict(p):
    doctor = User.query.filter_by(id=p.doctor_id).first()
    return {'id': p.id, "doctor": doctor.username, "name": p.username, "sex": "男" if p.sex == 0 else "女",
            "recordID": p.record_id, "age": p.age, "cva": p.cva, "info": p.info, "state": p.state,
            "result": p.result, "updateTime": p.update_time, "createTime": p.create_time}


def to_dicts(patients):
    res = []
    for p in patients:
        doctor = User.query.filter_by(id=p.doctor_id).first()
        res.append(
            {'id': p.id, "doctor": doctor.username, "name": p.username, "sex": "男" if p.sex == 0 else "女",
             "recordID": p.record_id, "age": p.age, "cva": p.cva, "info": p.info, "state": p.state,
             "result": p.result, "updateTime": p.update_time, "createTime": p.create_time})
    return res


def _add_patient(name, sex, age, info, result, recordID, state, cva):
    """
    添加病人或编辑病人状态
    :param name:
    :param sex:
    :param age:
    :param info:
    :param result:
    :param recordID:
    :param state:
    :return:
    """
    doctor = _get_current_user()
    patient = Patient.query.filter_by(record_id=recordID).first()
    if patient:
        patient.info = info
        patient.result = result
        patient.state = state
        patient.name = name
        patient.sex = sex
        patient.age = age
        patient.cva = cva
        db.session.commit()
        return to_dict(patient), "病人已存在，已更新数据"
    else:
        patient = Patient(name, recordID, state, doctor.id, age, sex, info, result, cva)
        db.session.add(patient)
        db.session.commit()
        return to_dict(patient), "病人已成功添加"


def _get_patients():
    """
    获取病人列表
    :return: patients
    """
    doctor = _get_current_user()
    if doctor.userType == 1:
        patients = db.session.query(Patient).order_by(Patient.update_time).all()
        return to_dicts(patients)
    else:
        patients = Patient.query.filter_by(doctor_id=doctor.id).all()
        return to_dicts(patients)


def _del_patient(id):
    """
    删除病人
    :param id:
    :return: boolean
    """
    patient = Patient.query.filter_by(id=id).first()
    if not patient:
        return False
    img_list = Img.query.filter_by(patient_id=patient.id).all()
    db.session.delete(patient)
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
    添加病人或编辑病人状态
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: 添加病人或编辑病人状态
          required:
            - name
          properties:
            name:
              type: string
              description: name
            sex:
              type: integer
              description: 0为男 1为女
            age:
              type: integer
              description: age
            info:
              type: string
              description: 病人基础信息
            result:
              type: string
              description: 检查结果
            recordID:
              type: string
              description: 病例ID
            state:
              type: string
              description: 病人状态
            cva:
              type: string
              description: 脑卒中分类
      - name: Authorization
        in: header
        type: string
        required: true
        description: token
    responses:
      fail:
        description: 添加病人失败
      success:
        description: 成加病人成功
    """
    try:
        json = request.get_json()
        name = json['name']
        sex = json['sex']
        age = json['age']
        info = json['info']
        result = json['result']
        recordID = json['recordID']
        state = json['state']
        cva = json['cva']
        patient, msg = _add_patient(name, sex, age, info, result, recordID, state, cva)
        response_object = {'patient': patient}
        return successReturn(response_object, msg)
    except Exception as e:
        return failReturn(format(e), "addPatient出错")


@app.route('/api/getPatients', methods=['GET'])
@login_required
@cross_origin()
def get_patients():
    """
    获取病人列表
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
        description: token
    responses:
      fail:
        description: 获取病人列表失败
      success:
        description: 获取病人列表成功
    """
    try:
        patientList = _get_patients()
        response_object = {'patientList': patientList}
        return successReturn(response_object, "getPatients： 获取病人列表成功")
    except Exception as e:
        return failReturn(format(e), "getPatients出错")


def _get_patient_id(id):
    """
    通过id获取病人
    :param id:
    :return: patient
    """
    patient = Patient.query.filter_by(id=id).first()
    if patient is None:
        return None
    doctor = _get_current_user()
    if doctor.userType == 1 or patient.doctor_id == doctor.id:
        return to_dict(patient)
    else:
        return None


@app.route('/api/getPatientByID', methods=['POST'])
@login_required
@cross_origin()
def get_patient_by_id():
    """
    根据id获取病人
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: 根据id获取病人
          required:
            - patientID
          properties:
            patientID:
              type: integer
              description: patientID
      - name: Authorization
        in: header
        type: string
        required: true
        description: token
    responses:
      fail:
        description: 获取病人失败
      success:
        description: 获取病人成功
    """
    try:
        json = request.get_json()
        patientID = json['patientID']
        patient = _get_patient_id(patientID)
        if not patient:
            return failReturn("", "getPatientByID: 获取病人失败")
        response_object = {'patient': patient}
        return successReturn(response_object, "getPatientByID: 获取病人成功")
    except Exception as e:
        return failReturn(format(e), "getPatientByID出错")


def _get_patient_name(username):
    """
        通过username获取病人
        :param username:
        :return: patient
        """
    patient = Patient.query.filter_by(username=username).first()
    if patient is None:
        return None
    doctor = _get_current_user()
    if doctor.userType == 1 or patient.doctor_id == doctor.id:
        return to_dict(patient)
    else:
        return None


@app.route('/api/getPatientByName', methods=['POST'])
@login_required
@cross_origin()
def get_patient_by_name():
    """
    根据username获取病人
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: 根据username获取病人
          required:
            - username
          properties:
            username:
              type: string
              description: username
      - name: Authorization
        in: header
        type: string
        required: true
        description: token
    responses:
      fail:
        description: 获取病人失败
      success:
        description: 获取病人成功
    """
    try:
        json = request.get_json()
        username = json['username']
        patient = _get_patient_name(username)
        if not patient:
            return failReturn("", "getPatientByName: 获取病人失败")
        response_object = {'patient': patient}
        return successReturn(response_object, "getPatientByName: 获取病人成功")
    except Exception as e:
        return failReturn(format(e), "getPatientByName出错")


@app.route('/api/delPatient', methods=['POST'])
@login_required
@cross_origin()
def del_patient():
    """
    删除病人
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: 删除病人
          required:
            - patientID
          properties:
            patientID:
              type: integer
              description: patientID
      - name: Authorization
        in: header
        type: string
        required: true
        description: token
    responses:
      fail:
        description: 删除失败
      success:
        description: 删除成功
    """
    try:
        patientID = request.get_json()['patientID']
        if not _del_patient(patientID):
            return failReturn("", "delPatient: 删除失败")
        return successReturn("", "delPatient: 删除成功")
    except Exception as e:
        return failReturn(format(e), "delPatient出错")


def _userType(u):
    if u.userType == 1:
        return "管理员"
    elif u.userType == 2:
        return "主任医生"
    else:
        return "医生"


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
        role = _userType(u)
        res.append({"id": u.id, "name": u.realname, "role": role})
    return res


@app.route('/api/userInfo', methods=['GET'])
@login_required
@cross_origin()
def user_info():
    """
    获取用户列表
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
        description: token
    responses:
      fail:
        description: 权限不足
      success:
        description: 获取用户列表成功
    """
    try:
        res = _statistics()
        if not res:
            return failReturn("", "userInfo: 权限不足")
        response_object = {'userInfo': res}
        return successReturn(response_object, "userInfo: 获取用户列表成功")
    except Exception as e:
        return failReturn(format(e), "userInfo出错")


@app.route('/api/userDetail', methods=['POST'])
@login_required
@cross_origin()
def user_detail():
    """
    获取用户详细信息
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: 获取用户详细信息
          required:
            - userID
          properties:
            userID:
              type: integer
              description: userID
      - name: Authorization
        in: header
        type: string
        required: true
        description: token
    responses:
      fail:
        description: 用户不存在
      success:
        description: 获取用户详细信息成功
    """
    try:
        userID = request.get_json()['userID']
        user = User.query.filter_by(id=userID).first()
        if not user:
            return failReturn("", "userDetail: 用户不存在")
        role = _userType(user)
        response_object = {'name': user.username, 'realname': user.realname, 'role': role}
        return successReturn(response_object, "userDetail； 获取用户详细信息成功")
    except Exception as e:
        return failReturn(format(e), "userDetail出错")


@app.route('/api/updateRole', methods=['POST'])
@login_required
@cross_origin()
def update_role():
    """
    更新用户权限
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: 更新用户权限
          required:
            - userID
            - role
          properties:
            userID:
              type: integer
              description: userID
            role:
              type: integer
              description: role 1管理员 2主任医生 3医生
      - name: Authorization
        in: header
        type: string
        required: true
        description: token
    responses:
      fail:
        description: 权限不足或用户不存在
      success:
        description: 更新权限成功
    """
    try:
        doctor = _get_current_user()
        userID = request.get_json()['userID']
        role = request.get_json()['role']
        if doctor.userType > role:
            return failReturn("", "updateRole; 权限不足")
        user = User.query.filter_by(id=userID).first()
        if not user:
            return failReturn("", "updateRole； 用户不存在")
        user.userType = role
        db.session.commit()
        return successReturn("", "updateRole: 更新权限成功")
    except Exception as e:
        return failReturn(format(e), "updateRole出错")


def to_list(patients):
    res = []
    manNumber = 0
    totalNumber = 0
    for p in patients:
        totalNumber += 1
        if p.sex == 0:
            manNumber += 1
        res.append({"sex": "男" if p.sex == 0 else "女", "age": p.age, "cva": p.cva})
    return res, manNumber, totalNumber


@app.route('/api/patientsAnalyze', methods=['GET'])
@login_required
@cross_origin()
def patients_analyze():
    """
    统计结果分析
    :return: json
    ---
    tags:
      - Manager API
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
        description: token
    responses:
      fail:
        description: 权限不足或用户不存在
      success:
        description: 更新权限成功
    """
    try:
        patients = db.session.query(Patient).order_by(Patient.update_time).all()
        cvaList, manNumber, totalNumber = to_list(patients)
        response_object = {'manNumber': manNumber, 'totalNumber': totalNumber, 'list': cvaList}
        return successReturn(response_object, "patientsAnalyze: 统计结果分析成功")
    except Exception as e:
        return failReturn(format(e), "patientsAnalyze出错")


# @app.route('/api/series', methods=['GET'])
# @cross_origin()
# def series():
#     """
#     生成随机uuid
#     :return:
#     ---
#     tags:
#       - Manager API
#     parameter:
#       - name: Authorization
#         in: header
#         type: string
#         required: true
#         description: token
#     responses:
#       success:
#         description: 生成随机uuid
#     """
#     try:
#         node = uuid.getnode()
#         mac = uuid.UUID(int=node).hex[-12:]
#         response_object = {'mac': mac}
#         return successReturn(response_object, "series: 生成随机uuid")
#     except Exception as e:
#         return failReturn(format(e), "series出错")


# def _get_img_list(id):
#     """
#     获取imgList
#     :param id:
#     :return: res
#     """
#     res = []
#     img_list = Img.query.filter_by(patient_id=id).order_by("timestamp").all()
#     for item in img_list:
#         res.append(
#             {
#                 "uploadname": item.uploadname,
#                 "timestamp": item.timestamp,
#                 "type": item.type,
#                 "filename": item.filename,
#                 "disabled": False
#             }
#         )
#     return res
#
#
# @app.route('/api/getDetail', methods=['POST'])
# @login_required
# @cross_origin()
# def get_detail():
#     """
#     获取病人详细信息
#     :return: json
#     ---
#     tags:
#       - Manager API
#     parameters:
#       - name: body
#         in: body
#         required: true
#         schema:
#           id: 根据id获取病人详细信息
#           required:
#             - patientID
#           properties:
#             patientID:
#               type: integer
#               description: patientID
#       - name: Authorization
#         in: header
#         type: string
#         required: true
#         description: token
#     responses:
#       fail:
#         description: 获取病人信息失败
#       success:
#         description: 获取病人信息成功
#     """
#     try:
#         json = request.get_json()
#         patientID = json['patientID']
#         patient = _get_patient_id(patientID)
#         if not patient:
#             return failReturn("", "getDetail: 获取病人信息失败")
#         img_list = _get_img_list(patientID)
#         response_object = {'patient': patient, 'imgs': img_list}
#         return successReturn(response_object, "getDetail: 获取病人信息成功")
#     except Exception as e:
#         return failReturn(format(e), "getDetail出错")
#
#
# @app.route('/api/imgList', methods=['POST'])
# @login_required
# @cross_origin()
# def get_img_list():
#     """
#     获取图像信息
#     :return: json
#     ---
#     tags:
#       - Manager API
#     parameters:
#       - name: body
#         in: body
#         required: true
#         schema:
#           id: 根据id获取病人详细信息
#           required:
#             - patientID
#           properties:
#             patientID:
#               type: integer
#               description: patientID
#       - name: Authorization
#         in: header
#         type: string
#         required: true
#         description: token
#     responses:
#       fail:
#         description: 获取图像列表失败
#       success:
#         description: 获取图像列表成功
#     """
#     try:
#         patientID = request.get_json()['patientID']
#         if not patientID:
#             return failReturn("", "imgList: 获取图像列表失败")
#         img_list = _get_img_list(patientID)
#         response_object = {'imgs': img_list}
#         return successReturn(response_object, "imgList: 获取图像列表成功")
#     except Exception as e:
#         return failReturn(format(e), "imgList出错")


# def _update_info(id, info, result, state):
#     """
#     更新信息
#     :param id:
#     :param info:
#     :return: boolean
#     """
#     patient = Patient.query.filter_by(id=id).first()
#     if not patient:
#         return False
#     patient.info = info
#     patient.result = result
#     patient.state = state
#     db.session.commit()
#     return True


# @app.route('/api/updateInfo', methods=['POST'])
# @login_required
# @cross_origin()
# def update_info():
#     """
#     更新用户信息
#     :return: json
#     ---
#     tags:
#       - Manager API
#     parameters:
#       - name: body
#         in: body
#         required: true
#         schema:
#           id: 更新用户信息
#           required:
#             - patientID
#           properties:
#             patientID:
#               type: integer
#               description: patientID
#             info:
#               type: string
#               description: info
#             result:
#               type: string
#               description: result
#             state:
#               type: string
#               description: state
#       - name: Authorization
#         in: header
#         type: string
#         required: true
#         description: token
#     responses:
#       fail:
#         description: 更新失败
#       success:
#         description: 更新成功
#     """
#     try:
#         json = request.get_json()
#         patientID = json['patientID']
#         info = json['info']
#         result = json['result']
#         state = json['state']
#         if not _update_info(patientID, info, result, state):
#             return failReturn("", "updateInfo: 更新失败")
#         return successReturn("", "updateInfo: 更新成功")
#     except Exception as e:
#         return failReturn(format(e), "updateInfo出错")


if __name__ == '__main__':
    def after_request(resp):
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        return resp


    app.after_request(after_request)
    app.run(debug=True, threaded=True, host='127.0.0.1', port=5050)
