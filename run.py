import os
import secrets

from api import app, db
from api.config import Config
from api.models import Role, User, Status


if __name__ == '__main__':
    """
    Подготавливает окружение, создаёт базу данных и запускает приложение.
    """

    # Установить переменные окружения
    secret_key = secrets.token_urlsafe(16)
    os.environ['SECRET_KEY'] = secret_key

    # Создать или открыть базу данных
    db.create_all()

    # Заполнить роли
    for key in Config.ACCOUNT_ROLES:
        if Role.query.filter_by(code=key).first() is None:
            role_object = Role(code=key, title=Config.ACCOUNT_ROLES[key])
            db.session.add(role_object)
            db.session.commit()

    # Заполнить статусы заявок
    for key in Config.REQUEST_STATUSES:
        if Status.query.filter_by(code=key).first() is None:
            status_object = Status(code=key, title=Config.REQUEST_STATUSES[key])
            db.session.add(status_object)
            db.session.commit()

    # Создать тестовые данные для отладки
    if app.config['DEBUG']:

        # Создать пользователей
        users = [
            {'username': 'user', 'password': 'user_password'},
            {'username': 'operator', 'password': 'operator_password'},
            {'username': 'admin', 'password': 'admin_password'},
        ]

        for user in users:
            if User.query.filter_by(username=user['username']).first() is None:
                user_object = User(username=user['username'])
                user_object.hash_password(user['password'])
                db.session.add(user_object)
                db.session.commit()

        # Назначить роли пользователям
        user_roles = [
            {'username': 'user', 'role': Config.USER_ROLE},
            {'username': 'operator', 'role': Config.USER_ROLE},
            {'username': 'operator', 'role': Config.OPERATOR_ROLE},
            {'username': 'admin', 'role': Config.ADMINISTRATOR_ROLE},
        ]

        for user in user_roles:
            user_object = User.query.filter_by(username=user['username']).first()
            role_object = Role.query.filter_by(code=user['role']).first()

            user_object.roles.append(role_object)
            db.session.commit()

    # Запустить приложение
    app.run(debug=app.config['DEBUG'])
