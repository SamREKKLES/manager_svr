## 技术栈

- 后端：Flask
- 数据库：sqlite3+Flask-SQLAlchemy
- 登陆管理：flask-login

## 项目结构

- manager_svr：用户管理后台

## 进展&TODO

- [x] 后端管理后台建立，数据库建表

## 数据库
- User表：注册医生的姓名，密码，权限等信息
- Patient表；存储患者拥有的CT图像，拥有他的医生

**当前设计为一个患者只对应一个医生，之后可以考虑建立多对多的数据表，让一个医生有多个患者，一个患者有多个医生**
"# manager_svr" 
