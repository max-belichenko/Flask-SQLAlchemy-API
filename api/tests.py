import base64
import os
import secrets
import unittest

from api.config import basedir, Config
from api import app, db
from api.models import *


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SECRET_KEY'] = secrets.token_urlsafe(16)
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'test.db')

        db.create_all()

        self.app = app.test_client()

    def tearDown(self) -> None:
        db.drop_all()

    def test_db_users(self):

        # Создать пользователя в базе данных
        username = 'username'
        password = 'password'

        user_object = User(username=username)
        user_object.hash_password(password)
        db.session.add(user_object)
        db.session.commit()

        # Проверить, что пользователь создан с указанными параметрами
        user_object = User.query.filter_by(username=username).first()
        self.assertEqual(user_object.username, username)
        self.assertTrue(user_object.verify_password(password))
        self.assertEqual(user_object.roles, [])

        # Создать роль в базе данных
        role_code = 'TEST_ROLE_CODE'
        role_title = 'This is a test role'
        role_object = Role(code=role_code, title=role_title)
        db.session.add(role_object)
        db.session.commit()

        # Назначить роль пользователю
        user_object.roles.append(role_object)
        db.session.commit()

        # Проверить, что пользователь создан с указанными параметрами
        user_object = User.query.filter_by(username=username).first()
        self.assertEqual(user_object.username, username)
        self.assertTrue(user_object.verify_password(password))
        self.assertEqual(user_object.roles, [role_object])

    def test_db_roles(self):
        code = 'code'
        title = 'title'

        role_object = Role(code=code, title=title)
        db.session.add(role_object)
        db.session.commit()

        role_object = Role.query.filter_by(code=code).first()
        self.assertEqual(role_object.code, code)
        self.assertEqual(role_object.title, title)

    def test_db_statuses(self):
        code = 'code'
        title = 'title'

        status_object = Status(code=code, title=title)
        db.session.add(status_object)
        db.session.commit()

        status_object = Status.query.filter_by(code=code).first()
        self.assertEqual(status_object.code, code)
        self.assertEqual(status_object.title, title)


class APITests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SECRET_KEY'] = secrets.token_urlsafe(16)
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'test.db')

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
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
            {'username': 'operator', 'role': Config.OPERATOR_ROLE},
            {'username': 'admin', 'role': Config.ADMINISTRATOR_ROLE},
        ]

        for user in user_roles:
            user_object = User.query.filter_by(username=user['username']).first()
            role_object = Role.query.filter_by(code=user['role']).first()

            user_object.roles.append(role_object)
            db.session.commit()

        self.app = app.test_client()

        self.test_users = ['user', 'operator', 'admin']
        self.admin_authorization = 'Basic ' + base64.b64encode('admin:admin_password'.encode('utf-8')).decode('ascii')
        self.operator_authorization = 'Basic ' + base64.b64encode('operator:operator_password'.encode('utf-8')).decode('ascii')
        self.user_authorization = 'Basic ' + base64.b64encode('user:user_password'.encode('utf-8')).decode('ascii')

    def tearDown(self):
        db.drop_all()

    def test_users_access(self):
        """
        Проверяет доступ к /users для различных ролей пользователей.

        :return:
        """
        address = '/users'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
        }

        # Проверяет, что разрешённые методы доступа открыты только для соответствующих ролей
        for auth in [self.admin_authorization]:
            headers['Authorization'] = auth
            result = self.app.get(address, headers=headers)
            self.assertEqual(result.status_code, 200)
            result = self.app.post(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.put(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.delete(address, headers=headers)
            self.assertEqual(result.status_code, 405)

        # Проверяет, что разрешённые методы доступа закрыты для соответствующих ролей
        for auth in [self.operator_authorization, self.user_authorization]:
            headers['Authorization'] = auth
            result = self.app.get(address, headers=headers)
            self.assertEqual(result.status_code, 403, f'"GET /users" - Access forbidden for {auth}')
            result = self.app.post(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.put(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.delete(address, headers=headers)
            self.assertEqual(result.status_code, 405)

    def test_get_users_created(self):
        """
        Проверяет возможность получить созданного пользователя.

        :return:
        """
        username = 'test_user'
        password = 'password'
        user = User(username=username)
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()

        address = '/users'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.admin_authorization,
        }
        result = self.app.get(address, headers=headers)
        data = result.get_json()

        for item in data:
            if item['id'] == user.id:
                self.assertEqual(item['username'], username,
                                 '"GET /users" - Created user - Check username')
                self.assertTrue(custom_app_context.verify(password, item['password_hash']),
                                '"GET /users" - Created user - Check password')
                self.assertEqual(item['roles'], [],
                                 '"GET /users" - Created user - Check roles')

    def test_user_access(self):
        """
        Проверяет доступ к /users/<id> для различных ролей пользователей.

        :return:
        """
        address = '/users/1'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
        }

        # Проверяет, что доступ открыт для соответствующих ролей
        for auth in [self.admin_authorization]:
            headers['Authorization'] = auth
            result = self.app.put(address, headers=headers, json='')
            self.assertEqual(result.status_code, 200, f'"GET /users" - Access granted')

        # Проверяет, что доступ закрыт для соответствующих ролей
        for auth in [self.operator_authorization, self.user_authorization]:
            headers['Authorization'] = auth
            result = self.app.put(address, headers=headers, json='')
            self.assertEqual(result.status_code, 403, f'"GET /users" - Access forbidden')

    def test_put_user_role(self):
        """
        Проверяет назначение роли пользователю.

        :return:
        """
        username = 'test_user'
        password = 'password'
        user = User(username=username)
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()

        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.admin_authorization,
        }

        address = f'/users/{user.id}'
        json = {
            'role': Config.ADMINISTRATOR_ROLE,
            'status': '1'
        }
        result = self.app.put(address, headers=headers, json=json)
        self.assertEqual(result.get_json()['error'], f'Could not assign role "{Config.ADMINISTRATOR_ROLE}"')

        address = f'/users/{user.id}'
        json = {
            'role': Config.OPERATOR_ROLE,
            'status': '2'
        }
        result = self.app.put(address, headers=headers, json=json)
        self.assertEqual(result.get_json()['error'], 'No such status "2"')

        address = f'/users/{user.id}'
        json = ''
        result = self.app.put(address, headers=headers, json=json)
        self.assertEqual(result.get_json()['error'], 'Received incorrect data. Awaiting JSON {"role", "status"}')

        address = f'/users/{user.id}'
        json = {
            'role': Config.OPERATOR_ROLE,
            'status': '1'
        }
        result = self.app.put(address, headers=headers, json=json)
        self.assertEqual(result.status_code, 200)

        address = '/users'
        result = self.app.get(address, headers=headers)
        data = result.get_json()

        for item in data:
            if item['id'] == user.id:
                roles = item['roles']
                self.assertEqual(len(roles), 1)
                self.assertEqual(roles[0]['code'], Config.OPERATOR_ROLE)
                break
        else:
            self.fail('User ID not found.')

        address = f'/users/{user.id}'
        json = {
            'role': Config.OPERATOR_ROLE,
            'status': '0'
        }
        result = self.app.put(address, headers=headers, json=json)
        self.assertEqual(result.status_code, 200)

        address = '/users'
        result = self.app.get(address, headers=headers)
        data = result.get_json()

        for item in data:
            if item['id'] == user.id:
                roles = item['roles']
                self.assertEqual(len(roles), 0)

        # data = result.get_json()
        # for user in data:
        #     self.assertIn(user['username'], users, '')
        #     for role in user['roles']:
        #         self.assertIn(role, Config.ACCOUNT_ROLES, '')

    def test_roles_access(self):
        """
        Проверяет доступ к /roles для различных ролей пользователей.

        :return:
        """
        address = '/roles'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
        }

        # Проверяет, что разрешённые методы доступа открыты только для соответствующих ролей
        for auth in [self.admin_authorization]:
            headers['Authorization'] = auth
            result = self.app.get(address, headers=headers)
            self.assertEqual(result.status_code, 200)
            result = self.app.post(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.put(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.delete(address, headers=headers)
            self.assertEqual(result.status_code, 405)

        # Проверяет, что разрешённые методы доступа закрыты для соответствующих ролей
        for auth in [self.operator_authorization, self.user_authorization]:
            headers['Authorization'] = auth
            result = self.app.get(address, headers=headers)
            self.assertEqual(result.status_code, 403)
            result = self.app.post(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.put(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.delete(address, headers=headers)
            self.assertEqual(result.status_code, 405)

    def test_get_roles_created(self):
        """
        Проверяет возможность получить созданную роль.

        :return:
        """
        code = 'test_role_code'
        title = 'test_role_title'
        role = Role(code=code, title=title)
        db.session.add(role)
        db.session.commit()

        address = '/roles'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.admin_authorization,
        }
        result = self.app.get(address, headers=headers)
        data = result.get_json()

        for item in data:
            if item['id'] == role.id:
                self.assertEqual(item['code'], code)
                self.assertEqual(item['title'], title)
                break
        else:
            self.fail('Role ID not found.')

    def test_requests_access(self):
        """
        Проверяет доступ к /requests для различных ролей пользователей.

        :return:
        """
        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
        }

        # Проверяет, что разрешённые методы доступа открыты только для соответствующих ролей
        for auth in [self.user_authorization]:
            headers['Authorization'] = auth
            result = self.app.get(address, headers=headers)
            self.assertEqual(result.status_code, 200)
            result = self.app.post(address, headers=headers)
            self.assertEqual(result.status_code, 400)
            result = self.app.post(address, headers=headers, json='')
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.get_json()['error'], 'Received incorrect data. Awaiting JSON {"text"}')
            result = self.app.put(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.delete(address, headers=headers)
            self.assertEqual(result.status_code, 405)

        # Проверяет, что разрешённые методы доступа закрыты для соответствующих ролей
        for auth in [self.operator_authorization, self.admin_authorization]:
            headers['Authorization'] = auth
            result = self.app.get(address, headers=headers)
            self.assertEqual(result.status_code, 403, f'GET {address}')
            result = self.app.post(address, headers=headers)
            self.assertEqual(result.status_code, 403, f'POST {address}')
            result = self.app.put(address, headers=headers)
            self.assertEqual(result.status_code, 405, f'PUT {address}')
            result = self.app.delete(address, headers=headers)
            self.assertEqual(result.status_code, 405, f'DELETE {address}')

    def test_get_requests(self):
        """
        Проверяет возможность получить заявку.

        :return:
        """
        username = 'user'
        status_code = Config.DRAFT_STATUS
        user = User.query.filter_by(username=username).first()
        status = Status.query.filter_by(code=status_code).first()
        status_id = status.id
        text = 'This is a test request.'

        object = Request(
            user=user,
            status=status,
            text=text
        )
        db.session.add(object)
        db.session.commit()

        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.get(address, headers=headers)
        data = result.get_json()

        for item in data:
            if item['id'] == object.id:
                self.assertIsNotNone(item['created_dt'])
                self.assertIsNone(item['updated_dt'])
                self.assertEqual(item['text'], 'This is a test request.')
                self.assertEqual(item['status_id'], status_id)
                break
        else:
            self.fail('Request ID not found.')

    def test_post_request_by_user(self):
        """
        Проверяет возможность Пользователя создать заявку .

        :return:
        """
        text = 'This is a test request.'

        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.post(address, headers=headers, json={'text': text})
        data = result.get_json()

        self.assertIsNotNone(data['created_dt'])
        self.assertIsNone(data['updated_dt'])
        self.assertEqual(data['status_id'], 1)
        self.assertEqual(data['text'], text)

    def test_post_request_by_opertaor(self):
        """
        Проверяет возможность Оператора создать заявку.

        :return:
        """
        text = 'This is a test request.'

        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.operator_authorization,
        }
        result = self.app.post(address, headers=headers, json={'text': text})
        self.assertEqual(result.status_code, 403)

    def test_post_request_by_administrator(self):
        """
        Проверяет возможность Администратора создать заявку.

        :return:
        """
        text = 'This is a test request.'

        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.admin_authorization,
        }
        result = self.app.post(address, headers=headers, json={'text': text})
        self.assertEqual(result.status_code, 403)

    def test_get_request_by_owner(self):
        """
        Проверяет возможность получить заявку Пользователем, который ей создал.

        :return:
        """
        username = 'user'
        status_code = Config.DRAFT_STATUS
        text = 'This is a test request.'

        user = User.query.filter_by(username=username).first()
        status = Status.query.filter_by(code=status_code).first()

        instance = Request(
            user=user,
            status=status,
            text=text
        )
        db.session.add(instance)
        db.session.commit()

        uri = f'/requests/{instance.id}'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.get(uri, headers=headers)

        data = result.get_json()

        self.assertEqual(data['id'], instance.id)

    def test_get_request_by_another_user(self):
        """
        Проверяет возможность получить заявку Пользователем, который не создавал её.

        :return:
        """

        # Создать заявку Пользователем user
        username = 'user'
        status_code = Config.DRAFT_STATUS
        text = 'This is a test request.'

        user = User.query.filter_by(username=username).first()
        status = Status.query.filter_by(code=status_code).first()

        request_instance = Request(
            user=user,
            status=status,
            text=text
        )
        db.session.add(request_instance)
        db.session.commit()

        # Создать нового пользователя test_user
        username = 'test_user'
        password = 'password'
        role_code = Config.USER_ROLE

        user = User(username=username)
        user.hash_password(password)

        role = Role.query.filter_by(code=role_code).first()
        user.roles.append(role)

        db.session.add(user)
        db.session.commit()

        # Проверить доступ к заявке нового пользователя
        uri = f'/requests/{request_instance.id}'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + base64.b64encode(f'{username}:{password}'.encode('utf-8')).decode('ascii'),
        }
        result = self.app.get(uri, headers=headers)

        data = result.get_json()

        self.assertEqual(result.status_code, 200)
        self.assertFalse(data)

    def test_get_request_by_operator(self):
        """
        Проверяет возможность получить заявку Оператором.

        :return:
        """

        # Создать заявку Пользователем user
        username = 'user'
        status_code = Config.DRAFT_STATUS
        text = 'This is a test request.'

        user = User.query.filter_by(username=username).first()
        status = Status.query.filter_by(code=status_code).first()

        request_instance = Request(
            user=user,
            status=status,
            text=text
        )
        db.session.add(request_instance)
        db.session.commit()

        # Проверить доступ к заявке Оператора
        uri = f'/requests/{request_instance.id}'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.operator_authorization,
        }
        result = self.app.get(uri, headers=headers)

        self.assertEqual(result.status_code, 403)

    def test_get_request_by_administrator(self):
        """
        Проверяет возможность получить заявку Администратором.

        :return:
        """

        # Создать заявку Пользователем user
        username = 'user'
        status_code = Config.DRAFT_STATUS
        text = 'This is a test request.'

        user = User.query.filter_by(username=username).first()
        status = Status.query.filter_by(code=status_code).first()

        request_instance = Request(
            user=user,
            status=status,
            text=text
        )
        db.session.add(request_instance)
        db.session.commit()

        # Проверить доступ к заявке Оператора
        uri = f'/requests/{request_instance.id}'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.admin_authorization,
        }
        result = self.app.get(uri, headers=headers)

        self.assertEqual(result.status_code, 403)

    def test_put_request_by_owner(self):
        """
        Проверяет возможность Пользователя изменить свою заявку .

        :return:
        """

        # Создать тестовую заявку
        text = 'This is a test request.'

        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.post(address, headers=headers, json={'text': text})
        data = result.get_json()
        request_id = data['id']

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['text'], text)

        # Проверить возможность изменить заявку
        updated_text = "Updated by owner"

        address = f'/requests/{request_id}'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.put(address, headers=headers, json={'text': updated_text})
        data = result.get_json()

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['text'], updated_text)

    def test_put_request_by_another_user(self):
        """
        Проверяет возможность Пользователя изменить чужую заявку .

        :return:
        """

        # Создать тестовую заявку
        text = 'This is a test request.'

        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.post(address, headers=headers, json={'text': text})
        data = result.get_json()
        request_id = data['id']

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['text'], text)

        # Создать нового пользователя test_user
        username = 'test_user'
        password = 'password'
        role_code = Config.USER_ROLE

        user = User(username=username)
        user.hash_password(password)

        role = Role.query.filter_by(code=role_code).first()
        user.roles.append(role)

        db.session.add(user)
        db.session.commit()

        # Проверить возможность изменить заявку
        updated_text = "Updated by owner"

        address = f'/requests/{request_id}'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + base64.b64encode(f'{username}:{password}'.encode('utf-8')).decode('ascii'),
        }
        result = self.app.put(address, headers=headers, json={'text': updated_text})
        data = result.get_json()

        self.assertEqual(result.status_code, 200)

        answer_message_starts_with = f'No request with id = {request_id} for user {user.id} "{username}"'
        self.assertEqual(data['error'][:len(answer_message_starts_with)], answer_message_starts_with)

    def test_put_request_by_operator(self):
        """
        Проверяет возможность Оператора изменить заявку .

        :return:
        """

        # Создать тестовую заявку
        text = 'This is a test request.'

        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.post(address, headers=headers, json={'text': text})
        data = result.get_json()
        request_id = data['id']

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['text'], text)

        # Проверить возможность изменить заявку
        updated_text = "Updated by operator"

        address = f'/requests/{request_id}'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.operator_authorization,
        }
        result = self.app.put(address, headers=headers, json={'text': updated_text})
        data = result.get_json()

        self.assertEqual(result.status_code, 403)

    def test_put_request_by_administrator(self):
        """
        Проверяет возможность Администратора изменить заявку .

        :return:
        """

        # Создать тестовую заявку
        text = 'This is a test request.'

        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.post(address, headers=headers, json={'text': text})
        data = result.get_json()
        request_id = data['id']

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['text'], text)

        # Проверить возможность изменить заявку
        updated_text = "Updated by admin"

        address = f'/requests/{request_id}'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.admin_authorization,
        }
        result = self.app.put(address, headers=headers, json={'text': updated_text})
        data = result.get_json()

        self.assertEqual(result.status_code, 403)

    def test_send_request_by_owner(self):
        """
        Проверяет возможность Пользователя отправить свою заявку.

        :return:
        """

        # Создать тестовую заявку
        text = 'This is a test request.'

        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.post(address, headers=headers, json={'text': text})
        data = result.get_json()
        request_id = data['id']

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['text'], text)

        # Проверить возможность отправить заявку на рассмотрение
        address = f'/requests/{request_id}/send'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.post(address, headers=headers)
        data = result.get_json()

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['id'], request_id)
        self.assertEqual(data['text'], text)
        self.assertEqual(data['status_id'], 2)

    def test_send_request_by_another_user(self):
        """
        Проверяет возможность Пользователя отправить чужую заявку .

        :return:
        """

        # Создать тестовую заявку
        text = 'This is a test request.'

        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.post(address, headers=headers, json={'text': text})
        data = result.get_json()
        request_id = data['id']

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['text'], text)

        # Создать нового пользователя test_user
        username = 'test_user'
        password = 'password'
        role_code = Config.USER_ROLE

        user = User(username=username)
        user.hash_password(password)

        role = Role.query.filter_by(code=role_code).first()
        user.roles.append(role)

        db.session.add(user)
        db.session.commit()

        # Проверить возможность изменить заявку
        address = f'/requests/{request_id}/send'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + base64.b64encode(f'{username}:{password}'.encode('utf-8')).decode('ascii'),
        }
        result = self.app.post(address, headers=headers)
        data = result.get_json()

        self.assertEqual(result.status_code, 200)

        answer_message_starts_with = f'No request with id = {request_id} for user {user.id} "{username}"'
        self.assertEqual(data['error'][:len(answer_message_starts_with)], answer_message_starts_with)

    def test_send_request_by_operator(self):
        """
        Проверяет возможность Оператора отправить чужую заявку.

        :return:
        """

        # Создать тестовую заявку
        text = 'This is a test request.'

        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.post(address, headers=headers, json={'text': text})
        data = result.get_json()
        request_id = data['id']

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['text'], text)

        # Проверить возможность изменить заявку
        address = f'/requests/{request_id}/send'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.operator_authorization,
        }
        result = self.app.post(address, headers=headers)
        data = result.get_json()

        self.assertEqual(result.status_code, 403)

    def test_send_request_by_administrator(self):
        """
        Проверяет возможность Администратора отправить чужую заявку.

        :return:
        """

        # Создать тестовую заявку
        text = 'This is a test request.'

        address = '/requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.user_authorization,
        }
        result = self.app.post(address, headers=headers, json={'text': text})
        data = result.get_json()
        request_id = data['id']

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['text'], text)

        # Проверить возможность изменить заявку
        address = f'/requests/{request_id}/send'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.admin_authorization,
        }
        result = self.app.post(address, headers=headers)
        data = result.get_json()

        self.assertEqual(result.status_code, 403)

    def test_get_sent_requests_access(self):
        """
        Проверяет доступ к /sent_requests для различных ролей пользователей.

        :return:
        """
        address = '/sent_requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
        }

        # Проверяет, что разрешённые методы доступа открыты только для соответствующих ролей
        for auth in [self.operator_authorization]:
            headers['Authorization'] = auth
            result = self.app.get(address, headers=headers)
            self.assertEqual(result.status_code, 200)
            result = self.app.post(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.put(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.delete(address, headers=headers)
            self.assertEqual(result.status_code, 405)

        # Проверяет, что разрешённые методы доступа закрыты для соответствующих ролей
        for auth in [self.user_authorization, self.admin_authorization]:
            headers['Authorization'] = auth
            result = self.app.get(address, headers=headers)
            self.assertEqual(result.status_code, 403, f'GET {address}')
            result = self.app.post(address, headers=headers)
            self.assertEqual(result.status_code, 405, f'POST {address}')
            result = self.app.put(address, headers=headers)
            self.assertEqual(result.status_code, 405, f'PUT {address}')
            result = self.app.delete(address, headers=headers)
            self.assertEqual(result.status_code, 405, f'DELETE {address}')

    def test_get_sent_request_by_operator(self):
        """
        Проверяет возможность Оператора получить список, содержащий одну заявку пользователя.

        :return:
        """

        # Создать заявки в статусе Отправлено
        username = 'user'
        status_code = Config.SENT_STATUS

        user = User.query.filter_by(username=username).first()
        status = Status.query.filter_by(code=status_code).first()

        text = f'This is a test request'
        request_instance = Request(
            user=user,
            status=status,
            text=text
        )
        db.session.add(request_instance)
        db.session.commit()

        uri = f'/sent_requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.operator_authorization,
        }
        result = self.app.get(uri, headers=headers)
        data = result.get_json()

        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['text'], 'T-h-i-s- -i-s- -a- -t-e-s-t- -r-e-q-u-e-s-t')

    def test_get_sent_requests_by_operator(self):
        """
        Проверяет возможность Оператора получить список отправленных заявок пользователей.

        :return:
        """

        # Создать заявки в статусе Отправлено
        username = 'user'
        status_code = Config.SENT_STATUS

        user = User.query.filter_by(username=username).first()
        status = Status.query.filter_by(code=status_code).first()

        for i in range(10):
            text = f'This is a test request #{i}'
            request_instance = Request(
                user=user,
                status=status,
                text=text
            )
            db.session.add(request_instance)
        db.session.commit()

        uri = f'/sent_requests'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.operator_authorization,
        }
        result = self.app.get(uri, headers=headers)
        data = result.get_json()

        self.assertEqual(len(data), 10)

        requests = [f'T-h-i-s- -i-s- -a- -t-e-s-t- -r-e-q-u-e-s-t- -#-{i}' for i in range(10)]
        for item in data:
            requests.pop(requests.index(item['text']))
        self.assertEqual(len(requests), 0)

    def test_accept_request_access(self):
        """
        Проверяет доступ к /requests/<id>/accept для различных ролей пользователей.

        :return:
        """

        # Создать заявки в статусе Отправлено
        username = 'user'
        user = User.query.filter_by(username=username).first()
        status_code = Config.SENT_STATUS
        status = Status.query.filter_by(code=status_code).first()
        text = f'This is a test request'

        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
        }

        # Проверяет, что разрешённые методы доступа открыты только для соответствующих ролей
        for auth in [self.operator_authorization]:
            request_instance = Request(user=user, status=status, text=text)
            db.session.add(request_instance)
            db.session.commit()

            address = f'/requests/{request_instance.id}/accept'

            headers['Authorization'] = auth
            result = self.app.get(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.post(address, headers=headers)
            self.assertEqual(result.status_code, 200)
            result = self.app.put(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.delete(address, headers=headers)
            self.assertEqual(result.status_code, 405)

        # Проверяет, что разрешённые методы доступа закрыты для соответствующих ролей
        for auth in [self.user_authorization, self.admin_authorization]:
            request_instance = Request(user=user, status=status, text=text)
            db.session.add(request_instance)
            db.session.commit()

            address = f'/requests/{request_instance.id}/accept'

            headers['Authorization'] = auth
            result = self.app.get(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.post(address, headers=headers)
            self.assertEqual(result.status_code, 403)
            result = self.app.put(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.delete(address, headers=headers)
            self.assertEqual(result.status_code, 405)

    def test_accept_request_by_operator(self):
        """
        Проверяет возможность Оператора принять заявку.

        :return:
        """

        # Создать заявки в статусе Отправлено
        username = 'user'
        user = User.query.filter_by(username=username).first()
        status_code = Config.SENT_STATUS
        status = Status.query.filter_by(code=status_code).first()
        text = f'This is a test request'

        request_instance = Request(user=user, status=status, text=text)
        db.session.add(request_instance)
        db.session.commit()

        # Проверить возможность принять заявку
        address = f'/requests/{request_instance.id}/accept'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.operator_authorization,
        }
        result = self.app.post(address, headers=headers)
        data = result.get_json()

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['id'], request_instance.id)
        self.assertEqual(data['text'], text)
        self.assertEqual(data['status_id'], 3)

    def test_accept_non_existent_request_by_operator(self):
        """
        Проверяет возможность Оператора принять несуществующую заявку.

        :return:
        """
        request_id = 'non-existent-request'

        # Проверить возможность принять заявку
        address = f'/requests/{request_id}/accept'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.operator_authorization,
        }
        result = self.app.post(address, headers=headers)
        data = result.get_json()

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['error'], f'No request with id = {request_id} with SENT status.')

    def test_accept_request_with_wrong_status_by_operator(self):
        """
        Проверяет возможность Оператора принять заявку в статусе, отличном от Отправлено.

        :return:
        """

        wrong_statuses = [
            Config.DRAFT_STATUS,
            Config.ACCEPTED_STATUS,
            Config.REJECTED_STATUS,
        ]

        username = 'user'
        user_instance = User.query.filter_by(username=username).first()
        text = f'This is a test request'

        for status in wrong_statuses:
            with self.subTest(status=status):

                # self.assertEqual(a, b, name)

                status_code = status
                status_instance = Status.query.filter_by(code=status_code).first()

                request_instance = Request(user=user_instance, status=status_instance, text=text)
                db.session.add(request_instance)
                db.session.commit()

                # Проверить возможность принять заявку
                address = f'/requests/{request_instance.id}/accept'
                headers = {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json',
                    'Authorization': self.operator_authorization,
                }
                result = self.app.post(address, headers=headers)
                data = result.get_json()

                self.assertEqual(result.status_code, 200)
                self.assertEqual(data['error'], f'No request with id = {request_instance.id} with SENT status.', status)

    def test_reject_request_access(self):
        """
        Проверяет доступ к /requests/<id>/reject для различных ролей пользователей.

        :return:
        """

        # Создать заявки в статусе Отправлено
        username = 'user'
        user = User.query.filter_by(username=username).first()
        status_code = Config.SENT_STATUS
        status = Status.query.filter_by(code=status_code).first()
        text = f'This is a test request'

        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
        }

        # Проверяет, что разрешённые методы доступа открыты только для соответствующих ролей
        for auth in [self.operator_authorization]:
            request_instance = Request(user=user, status=status, text=text)
            db.session.add(request_instance)
            db.session.commit()

            address = f'/requests/{request_instance.id}/reject'

            headers['Authorization'] = auth
            result = self.app.get(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.post(address, headers=headers)
            self.assertEqual(result.status_code, 200)
            result = self.app.put(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.delete(address, headers=headers)
            self.assertEqual(result.status_code, 405)

        # Проверяет, что разрешённые методы доступа закрыты для соответствующих ролей
        for auth in [self.user_authorization, self.admin_authorization]:
            request_instance = Request(user=user, status=status, text=text)
            db.session.add(request_instance)
            db.session.commit()

            address = f'/requests/{request_instance.id}/reject'

            headers['Authorization'] = auth
            result = self.app.get(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.post(address, headers=headers)
            self.assertEqual(result.status_code, 403)
            result = self.app.put(address, headers=headers)
            self.assertEqual(result.status_code, 405)
            result = self.app.delete(address, headers=headers)
            self.assertEqual(result.status_code, 405)

    def test_reject_request_by_operator(self):
        """
        Проверяет возможность Оператора отклонять заявку.

        :return:
        """

        # Создать заявки в статусе Отправлено
        username = 'user'
        user = User.query.filter_by(username=username).first()
        status_code = Config.SENT_STATUS
        status = Status.query.filter_by(code=status_code).first()
        text = f'This is a test request'

        request_instance = Request(user=user, status=status, text=text)
        db.session.add(request_instance)
        db.session.commit()

        # Проверить возможность принять заявку
        address = f'/requests/{request_instance.id}/reject'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.operator_authorization,
        }
        result = self.app.post(address, headers=headers)
        data = result.get_json()

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['id'], request_instance.id)
        self.assertEqual(data['text'], text)
        self.assertEqual(data['status_id'], 4)

    def test_reject_non_existent_request_by_operator(self):
        """
        Проверяет возможность Оператора отклонить несуществующую заявку.

        :return:
        """
        request_id = 'non-existent-request'

        # Проверить возможность принять заявку
        address = f'/requests/{request_id}/reject'
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'Authorization': self.operator_authorization,
        }
        result = self.app.post(address, headers=headers)
        data = result.get_json()

        self.assertEqual(result.status_code, 200)
        self.assertEqual(data['error'], f'No request with id = {request_id} with SENT status.')

    def test_reject_request_with_wrong_status_by_operator(self):
        """
        Проверяет возможность Оператора отклонить заявку в статусе, отличном от Отправлено.

        :return:
        """

        wrong_statuses = [
            Config.DRAFT_STATUS,
            Config.ACCEPTED_STATUS,
            Config.REJECTED_STATUS,
        ]

        username = 'user'
        user_instance = User.query.filter_by(username=username).first()
        text = f'This is a test request'

        for status in wrong_statuses:
            with self.subTest(status=status):
                status_code = status
                status_instance = Status.query.filter_by(code=status_code).first()

                request_instance = Request(user=user_instance, status=status_instance, text=text)
                db.session.add(request_instance)
                db.session.commit()

                # Проверить возможность принять заявку
                address = f'/requests/{request_instance.id}/reject'
                headers = {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json',
                    'Authorization': self.operator_authorization,
                }
                result = self.app.post(address, headers=headers)
                data = result.get_json()

                self.assertEqual(result.status_code, 200)
                self.assertEqual(data['error'], f'No request with id = {request_instance.id} with SENT status.', status)


if __name__ == '__main__':
    unittest.main()
