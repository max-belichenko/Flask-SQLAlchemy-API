import os


basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    """
    Класс содержит параметры работы приложения:
    """

    # Режит отладки
    DEBUG = True

    # Секретный ключ
    SECRET_KEY = os.environ.get('SECRET_KEY')

    # Подключение к базе данных
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')

    # Список ролей пользователей
    USER_ROLE = 'USER'
    OPERATOR_ROLE = 'OPERATOR'
    ADMINISTRATOR_ROLE = 'ADMINISTRATOR'

    ACCOUNT_ROLES = {
        USER_ROLE: 'Пользователь',
        OPERATOR_ROLE: 'Оператор',
        ADMINISTRATOR_ROLE: 'Администратор',
    }

    # Список статусов заявок
    DRAFT_STATUS = 'DRAFT'
    SENT_STATUS = 'SENT'
    ACCEPTED_STATUS = 'ACCEPTED'
    REJECTED_STATUS = 'REJECTED'

    REQUEST_STATUSES = {
        DRAFT_STATUS: 'Черновик',
        SENT_STATUS: 'Отправлено',
        ACCEPTED_STATUS: 'Принято',
        REJECTED_STATUS: 'Отклонено',
    }
