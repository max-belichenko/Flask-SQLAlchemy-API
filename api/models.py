from datetime import datetime

from marshmallow import pre_dump
from passlib.apps import custom_app_context

from api import db, ma


# Промежуточная таблица для связи many-to-many между таблицами users и roles
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)


class User(db.Model):
    """
    Модель Пользователя:

        id - идентификатор пользователя (создаётся автоматически)
        username - имя пользователя (должно быть уникальным)
        password_hash - хэш пароля
        roles - список ролей, назаченных пользователю
        requests - список заявок, открытых пользователем
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    roles = db.relationship('Role', secondary=user_roles, lazy='subquery', backref=db.backref('users', lazy=True))
    requests = db.relationship('Request', backref='user', lazy=True)

    def hash_password(self, password):
        """
        Вычисляет хэш пароля и сохраняет хэш в поле password_hash.

        :param password:
        :return:
        """
        self.password_hash = custom_app_context.encrypt(password)

    def verify_password(self, password):
        """
        Вычисляет хэш пароля и сравнивает с сохранённым хэшем.

        :param password:
        :return:
        """
        return custom_app_context.verify(password, self.password_hash)

    def __repr__(self):
        """
        Возвращает строковое представление объекта.

        :return:
        """
        return f'{self.id} "{self.username}" {self.roles}'


class UserSchema(ma.Schema):
    """
    Описывает сериализацию объекта Пользователя.
    """
    # Ссылка не класс сериализации объекта Роли
    roles = ma.Nested('RoleSchema', many=True)

    class Meta:
        # Список полей, доступных при сериализации
        fields = ('id', 'username', 'password_hash', 'roles')


class Role(db.Model):
    """
    Модель Роли пользователя:

        id - идентификатор роли (создаётся автоматически)
        code - код роли (настраивается в файле конфигурации config.py)
        title - название или краткое описание роли
    """
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), index=True)
    title = db.Column(db.String(128))

    def __repr__(self):
        """
        Возвращает строковое представление объекта.

        :return:
        """
        return f'[{self.id}] {self.code} "{self.title}"'


class RoleSchema(ma.Schema):
    """
    Описывает сериализацию объекта Пользователя.
    """
    class Meta:
        # Список полей, доступных при сериализации
        fields = ('id', 'code', 'title',)


class Request(db.Model):
    """
    Модель Заявки:

        id - идентификатор заявки (создаётся автоматически)
        created_dt - дата создания заявки (заполняется автоматически при создании заявки)
        updated_dt - дата изменения заявки (заполняется автоматически при изменении заявки)
        user_id - ссылка на идентификатор пользователя
        status_id - ссылка на идентификатор статуса заявки
        text - текстовое описание заявки
    """
    __tablename__ = 'requests'

    id = db.Column(db.Integer, primary_key=True)
    created_dt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_dt = db.Column(db.DateTime, onupdate=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status_id = db.Column(db.Integer, db.ForeignKey('statuses.id'), nullable=False)

    text = db.Column(db.Text, nullable=False)

    def __repr__(self):
        """
        Возвращает строковое представление объекта.

        :return:
        """
        return f'Request #{self.id} created at {self.created_dt}: "{self.text}"'


class RequestSchema(ma.Schema):
    """
    Описывает сериализацию объекта Заявки.
    """
    class Meta:
        # Список полей, доступных при сериализации
        fields = ('id', 'created_dt', 'updated_dt', 'user_id', 'status_id', 'text')


class OperateRequestSchema(ma.Schema):
    """
    Описывает сериализацию объекта Заявки.
    """
    class Meta:
        # Список полей, доступных при сериализации
        fields = ('id', 'created_dt', 'updated_dt', 'user_id', 'status_id', 'text')

    @pre_dump
    def text_for_operator(self, in_data, **kwargs):
        """
        Изменяет значение поля text, вставляя символ "-" между всеми символами.

        :param in_data: Объект модели Request
        :param kwargs:
        :return: Изменённый объект
        """
        text = in_data.text
        text_length = len(text)
        updated_text = ''.join(
            [
                ('-' if i>=1 else '') + text[i]
                for i in range(text_length)
            ]
        )
        in_data.text = updated_text
        return in_data


class Status(db.Model):
    """
    Модель Статуса заявки:

        id - идентификатор статуса (создаётся автоматически)
        code - код статуса (настраивается в файле конфигурации config.py)
        title - название или краткое описание статуса
        requests - список заявок в каждом статусе
    """
    __tablename__ = 'statuses'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), index=True)
    title = db.Column(db.String(128))

    requests = db.relationship('Request', backref='status', lazy=True)

    def __repr__(self):
        """
        Возвращает строковое представление объекта.

        :return:
        """
        return f'[{self.id}] {self.code} "{self.title}"'


class StatusSchema(ma.Schema):
    """
    Описывает сериализацию объекта Статуса заявки.
    """
    class Meta:
        # Список полей, доступных при сериализации
        fields = ('id', 'code', 'title',)
