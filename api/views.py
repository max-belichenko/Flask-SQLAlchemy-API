from flask import request, jsonify

from api import app, auth, db
from api.config import Config
from api.models import User, UserSchema, Role, RoleSchema, Request, Status, RequestSchema, OperateRequestSchema


@auth.verify_password
def verify_password(username, password):
    """
    Проверяет пароль пользователя.
    Используется при аутентификации пользователя модулем HTTPBasicAuth.

    :param username: имя пользователя
    :param password: пароль
    :return:    True - пользователь прошёл аутентификацию
                False - неверное имя пользователя или пароль
    """
    user = User.query.filter_by(username=username).first()
    if not user or not user.verify_password(password):
        return False
    else:
        return True


@auth.get_user_roles
def get_user_roles(user):
    """
    Получает список ролей, назначенных пользователю.
    Используется при авторизации авторизации пользователя модулем HTTPBasicAuth.

    :param user: словарь, который содержит ключ "username" с именем пользователя
    :return:    список ролей пользователя
    """
    user_object = User.query.filter_by(username=user['username']).first()
    roles_schema = RoleSchema(many=True)
    roles_dump = roles_schema.dump(user_object.roles)
    roles_list = [role['code'] for role in roles_dump]

    return roles_list


# Функция заблокирована в соответствии с заданием.
#
# @app.route('/users', methods=['POST'])
# def new_user():
#     """
#     Регистрирует нового пользователя.
#     Пользователь создаётся без какой-либо назначенной роли. Роль должен назначить администратор.
#
#     Входные данные - JSON:
#         "username": "имя пользователя"
#         "password": "пароль"
#
#     :return: JSON объект созданного пользователя
#     """
#     username = request.json.get('username')
#     password = request.json.get('password')
#
#     if username is None or password is None:
#         return jsonify({'error': 'username or password is missing'})
#
#     if User.query.filter_by(username=username).first() is not None:
#         return jsonify({'error': 'username already exists'})
#
#     user = User(username=username)
#     user.hash_password(password)
#
#     db.session.add(user)
#     db.session.commit()
#
#     user_schema = UserSchema()
#
#     return user_schema.jsonify(user)


@app.route('/users', methods=['GET'])
@auth.login_required(role=Config.ADMINISTRATOR_ROLE)
def get_users():
    """
    Получает список всех пользователей.
    Доступно только для пользователей с ролью администратора (code = "ADMINISTRATOR").

    :return: JSON список пользователей
    """
    users = User.query.all()
    users_schema = UserSchema(many=True)

    result = users_schema.dump(users)

    return jsonify(result)


# Назначить роль пользователю
@app.route('/users/<id>', methods=['PUT'])
@auth.login_required(role=Config.ADMINISTRATOR_ROLE)
def change_user_roles(id):
    """
    Назначает роли для пользователя.
    Доступно только для пользователей с ролью администратора (code = "ADMINISTRATOR").
    Администратор может назначить или удалить только роль Оператора (code = "OPERATOR").

    Входные данные - объект или список объектов JSON:
        "role": "код роли"
        "staus": "статус"

    где код роли указывается в соответствии с полем code таблицы roles (см. конфигурационный файл config.py);
    статус может принимать занчение "0" - удалить роль или "1" - назначить роль.

    :return: JSON объект пользователя с применёнными изменениями
    """
    user_object = User.query.get(id)
    if user_object is None:
        return jsonify({'error': f'No user with id = {id}'})

    data = request.get_json()
    if data is None:
        return jsonify({'error': 'Received incorrect data. Awaiting JSON {"role", "status"}'})
    elif not isinstance(data, list):  # Если передан только один статус
        data = [data, ]

    for item in data:
        try:
            role_code = item['role']
            role_status = item['status']
        except (KeyError, TypeError):
            return jsonify({'error': 'Received incorrect data. Awaiting JSON {"role", "status"}'})

        role_object = Role.query.filter_by(code=role_code).first()
        if not role_object:
            return jsonify({'error': f'No such role "{role_code}"'})
        elif role_object.code != Config.OPERATOR_ROLE:
            return jsonify({'error': f'Could not assign role "{role_code}"'})

        if role_status == '1':  # Добавить роль пользователю
            user_object.roles.append(role_object)
        elif role_status == '0':    # Удалить роль у пользователя
            try:
                user_object.roles.remove(role_object)
            except ValueError:  # У пользователя отсутствует роль, которую пытается удалить.
                print(f'Warning! Role {role_object} is not attached to this user. Remove is skipped.')
        else:
            return jsonify({'error': f'No such status "{role_status}"'})

    db.session.commit()

    user_schema = UserSchema()

    return user_schema.jsonify(user_object)


@app.route('/roles', methods=['GET'])
@auth.login_required(role=Config.ADMINISTRATOR_ROLE)
def get_roles():
    """
    Получает список всех доступных ролей пользователей.
    Доступно только для пользователей с ролью администратора (code = "ADMINISTRATOR").

    :return: JSON список ролей
    """
    roles = Role.query.all()
    roles_schema = RoleSchema(many=True)

    result = roles_schema.dump(roles)

    return jsonify(result)


@app.route('/requests', methods=['POST'])
@auth.login_required(role=Config.USER_ROLE)
def new_request():
    """
    Создаёт новую заявку.
    Доступно только для пользователей с ролью пользователя (code = "USER").

    Входные данные - объект или список объектов JSON:
        "text": "текст заявки"

    Заявка создаётся в статусе Черновик (code = "DRAFT").
    При этом автоматически заполняются поля:
        user_id - идентификатор пользователя, создавшего заявку
        status_id - идентификатор статуса заявки
        created_dt - дата и время создания заявки

    :return: JSON объект заявки
    """
    try:
        text = request.json.get('text')
    except AttributeError:
        return jsonify({'error': 'Received incorrect data. Awaiting JSON {"text"}'})

    if text is None:
        return jsonify({'error': 'text is missing'})

    user = User.query.filter_by(username=auth.current_user()).first()
    status = Status.query.filter_by(code=Config.DRAFT_STATUS).first()

    request_object = Request(
        user=user,
        status=status,
        text=text
    )

    db.session.add(request_object)
    db.session.commit()

    request_schema = RequestSchema()

    return request_schema.jsonify(request_object)


@app.route('/requests', methods=['GET'])
@auth.login_required(role=Config.USER_ROLE)
def get_requests():
    """
    Получает список всех заявок пользователя.
    Доступно только для пользователей с ролью пользователя (code = "USER").

    :return: JSON список заявок пользователя
    """
    user = User.query.filter_by(username=auth.current_user()).first()

    request_objects = Request.query.filter_by(user=user).order_by(Request.created_dt.desc()).all()
    request_schema = RequestSchema(many=True)

    result = request_schema.dump(request_objects)

    return jsonify(result)


@app.route('/requests/<id>', methods=['GET'])
@auth.login_required(role=Config.USER_ROLE)
def get_request(id):
    """
    Получает указанную заявку пользователя.
    Доступно только для пользователей с ролью пользователя (code = "USER").

    :return: JSON объект заявки пользователя
    """
    user = User.query.filter_by(username=auth.current_user()).first()

    request_objects = Request.query.filter_by(id=id, user=user).first()
    request_schema = RequestSchema()

    result = request_schema.dump(request_objects)

    return jsonify(result)


@app.route('/requests/<id>', methods=['PUT'])
@auth.login_required(role=Config.USER_ROLE)
def change_request(id):
    """
    Изменяет существующую заявку.
    Доступно только для пользователей с ролью пользователя (code = "USER").
    Доступно только для заявок в статусе Черновик (code = "DRAFT").

    Входные данные - объект или список объектов JSON:
        "text": "текст заявки"

    Меняется текст заявки на переданный.
    При этом автоматически заполняются поля:
        updated_dt - дата и время обновления заявки

    :return: JSON объект изменённой заявки
    """
    user = User.query.filter_by(username=auth.current_user()).first()

    request_object = Request.query.filter_by(id=id, user=user).first()
    if request_object is None:
        return jsonify({'error': f'No request with id = {id} for user {user}'})
    elif request_object.status.code != Config.DRAFT_STATUS:
        return jsonify({'error': f'Can\'t modify request with status {request_object.status.code}'})

    text = request.json.get('text')
    if text is None:
        return jsonify({'error': 'text is missing'})

    request_object.text = text

    db.session.commit()

    request_schema = RequestSchema()
    result = request_schema.dump(request_object)

    return jsonify(result)


@app.route('/requests/<id>/send', methods=['POST'])
@auth.login_required(role=Config.USER_ROLE)
def send_request(id):
    """
    Отправляет заявку на рассмотрение оператору.
    Доступно только для пользователей с ролью пользователя (code = "USER").
    Доступно только для заявок в статусе Черновик (code = "DRAFT").

    Заявка переводится в статус Отправлено (code = "SENT")

    При этом автоматически обновляются поля:
        updated_dt - дата и время обновления заявки
        status_id - идентификатор статуса заявки

    :return: JSON объект изменённой заявки
    """
    user = User.query.filter_by(username=auth.current_user()).first()

    request_object = Request.query.filter_by(id=id, user=user).first()
    if request_object is None:
        return jsonify({'error': f'No request with id = {id} for user {user}'})
    elif request_object.status.code != Config.DRAFT_STATUS:
        return jsonify({'error': f'Can\'t send request with status {request_object.status.code}'})

    status_object = Status.query.filter_by(code=Config.SENT_STATUS).first()

    request_object.status = status_object

    db.session.commit()

    request_schema = RequestSchema()
    result = request_schema.dump(request_object)

    return jsonify(result)


@app.route('/sent_requests', methods=['GET'])
@auth.login_required(role=Config.OPERATOR_ROLE)
def get_sent_requests():
    """
    Получает список заявок, отправленных на рассмотрение всеми пользователями.
    Доступно только для пользователей с ролью оператора (code = "OPERATOR").

    В список помещаются только заявки в статусе Отправлено (code = "SENT").

    :return: JSON список заявок
    """
    status_object = Status.query.filter_by(code=Config.SENT_STATUS).first()

    request_objects = Request.query.filter_by(status=status_object).order_by(Request.created_dt.desc()).all()
    request_schema = OperateRequestSchema(many=True)

    result = request_schema.dump(request_objects)

    return jsonify(result)


@app.route('/requests/<id>/accept', methods=['POST'])
@auth.login_required(role=Config.OPERATOR_ROLE)
def accept_request(id):
    """
    Переводит заявку в статус Принято.
    Доступно только для пользователей с ролью оператора (code = "OPERATOR").
    Доступно только для заявок в статусе Отправлено (code = "SENT").

    Заявка переводится в статус Принято (code = "ACCEPTED")

    При этом автоматически обновляются поля:
        updated_dt - дата и время обновления заявки
        status_id - идентификатор статуса заявки

    :return: JSON объект изменённой заявки
    """
    status_object = Status.query.filter_by(code=Config.SENT_STATUS).first()
    request_object = Request.query.filter_by(id=id, status=status_object).first()
    if request_object is None:
        return jsonify({'error': f'No request with id = {id} with {Config.SENT_STATUS} status.'})

    status_object = Status.query.filter_by(code=Config.ACCEPTED_STATUS).first()

    request_object.status = status_object

    db.session.commit()

    request_schema = RequestSchema()
    result = request_schema.dump(request_object)

    return jsonify(result)


@app.route('/requests/<id>/reject', methods=['POST'])
@auth.login_required(role=Config.OPERATOR_ROLE)
def reject_request(id):
    """
    Переводит заявку в статус Отклонено.
    Доступно только для пользователей с ролью оператора (code = "OPERATOR").
    Доступно только для заявок в статусе Отправлено (code = "SENT").

    Заявка переводится в статус Отклонено (code = "REJECTED")

    При этом автоматически обновляются поля:
        updated_dt - дата и время обновления заявки
        status_id - идентификатор статуса заявки

    :return: JSON объект изменённой заявки
    """
    status_object = Status.query.filter_by(code=Config.SENT_STATUS).first()
    request_object = Request.query.filter_by(id=id, status=status_object).first()
    if request_object is None:
        return jsonify({'error': f'No request with id = {id} with {Config.SENT_STATUS} status.'})

    status_object = Status.query.filter_by(code=Config.REJECTED_STATUS).first()

    request_object.status = status_object

    db.session.commit()

    request_schema = RequestSchema()
    result = request_schema.dump(request_object)

    return jsonify(result)
