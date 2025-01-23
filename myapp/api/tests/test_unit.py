import json
import datetime
import jwt
from django.conf import settings
from constance import config
from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework.test import APITestCase
from rest_framework import status
from api.models import RefreshToken


def do_post_request(url, body, status_code, response_json):
    def wrapper(self):
        response = self.client.post(reverse(url), data=body)
        self.assertEqual(response.status_code, status_code)
        self.assertJSONEqual(response.content, response_json)
    return wrapper

def do_get_request(url, headers, status_code, response_json):
    def wrapper(self):
        response = self.client.get(reverse(url), headers=headers)
        self.assertEqual(response.status_code, status_code)
        self.assertJSONEqual(response.content, response_json)
    return wrapper

def do_put_request(url, headers, body, status_code, response_json):
    def wrapper(self):
        response = self.client.put(reverse(url), headers=headers, data=body)
        self.assertEqual(response.status_code, status_code)
        self.assertJSONEqual(response.content, response_json)
    return wrapper


class RegisterTestCase(APITestCase):

    test_register_no_data = do_post_request('api:register',
                                            None,
                                            status.HTTP_400_BAD_REQUEST,
                                            {"password": ["This field is required."],
                                             "email": ["This field is required."] })

    test_register_password_only = do_post_request('api:register',
                                                  {'password': '1234567891234'},
                                                  status.HTTP_400_BAD_REQUEST,
                                                  {"email": ["This field is required."]})

    test_register_email_only = do_post_request('api:register',
                                               {'email': 'sdf@mail.ru'},
                                               status.HTTP_400_BAD_REQUEST,
                                               {"password": ["This field is required."]})

    test_register_too_long_password = do_post_request('api:register',
                                                      {'email': 'sdf@mail.ru', 'password': '11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'},
                                                      status.HTTP_400_BAD_REQUEST,
                                                      {"password": ["Ensure this field has no more than 100 characters."]})

    test_register_too_short_password = do_post_request('api:register',
                                                       {'email': 'sdf@mail.ru', 'password': '1'},
                                                       status.HTTP_400_BAD_REQUEST,
                                                       {"password": ["Ensure this field has at least 12 characters."]})

    test_register_blank_password = do_post_request('api:register',
                                                   {'email': 'sdf@mail.ru', 'password': ''},
                                                   status.HTTP_400_BAD_REQUEST,
                                                   {"password": ["This field may not be blank."]})

    test_register_incorrect_email = do_post_request('api:register',
                                                    {'email': 'dfcgvhbjnkm', 'password': 'sdkfjnskdjfnjsdfjkn'},
                                                    status.HTTP_400_BAD_REQUEST,
                                                    {"email": ["Enter a valid email address."]})

    test_register_blank_email = do_post_request('api:register',
                                                {'email': '', 'password': 'sdkfjnskdjfnjsdfjkn'},
                                                status.HTTP_400_BAD_REQUEST,
                                                {"email": ["This field may not be blank."]})

    def test_register_valid_data(self):
        users = User.objects.count()
        self.assertEqual(users, 0)

        do_post_request('api:register',
                        {'email': 'user12345@mail.ru', 'password': 'sdkfjnskdjfnjsdfjkn'},
                        status.HTTP_201_CREATED,
                        {"id": 1, "email": "user12345@mail.ru"})(self)

        users = User.objects.all()
        self.assertEqual(users.count(), 1)
        user = users.get(id=1)
        self.assertEqual(user.email, "user12345@mail.ru")

    def test_register_twice(self):
        users = User.objects.count()
        self.assertEqual(users, 0)

        do_post_request('api:register',
                        {'email': 'user12345@mail.ru', 'password': 'sdkfjnskdjfnjsdfjkn'},
                        status.HTTP_201_CREATED,
                        {"id": 1, "email": "user12345@mail.ru"})(self)

        do_post_request('api:register',
                        {'email': 'user12345@mail.ru', 'password': 'sdkfjnskdjfnjsdfjkn'},
                        status.HTTP_400_BAD_REQUEST,
                        {"detail": 'User cannot be created!'})(self)


class LoginTestCase(APITestCase):
    test_login_no_data = do_post_request('api:login',
                                         None,
                                         status.HTTP_400_BAD_REQUEST,
                                         {"password": ["This field is required."],
                                          "email": ["This field is required."] })

    test_login_password_only = do_post_request('api:login',
                                               {'password': '1234567891234'},
                                               status.HTTP_400_BAD_REQUEST,
                                               {"email": ["This field is required."]})

    test_login_email_only = do_post_request('api:login',
                                            {'email': 'sdf@mail.ru'},
                                            status.HTTP_400_BAD_REQUEST,
                                            {"password": ["This field is required."]})

    test_login_too_long_password = do_post_request('api:login',
                                                   {'email': 'sdf@mail.ru',
                                                    'password': '11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'},
                                                   status.HTTP_400_BAD_REQUEST,
                                                   {"password": ["Ensure this field has no more than 100 characters."]})

    test_login_too_short_password = do_post_request('api:login',
                                                    {'email': 'sdf@mail.ru', 'password': '1'},
                                                    status.HTTP_400_BAD_REQUEST,
                                                    {"password": ["Ensure this field has at least 12 characters."]})

    test_login_blank_password = do_post_request('api:login',
                                                    {'email': 'sdf@mail.ru', 'password': ''},
                                                    status.HTTP_400_BAD_REQUEST,
                                                    {"password": ["This field may not be blank."]})


    test_login_incorrect_email = do_post_request('api:login',
                                                 {'email': 'dfcgvhbjnkm', 'password': 'sdkfjnskdjfnjsdfjkn'},
                                                 status.HTTP_400_BAD_REQUEST,
                                                 {"email": ["Enter a valid email address."]})

    test_login_blank_email = do_post_request('api:login',
                                             {'email': '', 'password': 'sdkfjnskdjfnjsdfjkn'},
                                             status.HTTP_400_BAD_REQUEST,
                                             {"email": ["This field may not be blank."]})

    test_login_not_existing_user = do_post_request('api:login',
                                                   {'email': 'user1mail@mail.ru', 'password': 'password12345'},
                                                   status.HTTP_403_FORBIDDEN,
                                                   {'detail': 'No such user!'})

    def test_login(self):
        user = User.objects.create_user('user1', 'user1mail@mail.ru', password='password12345')
        response = self.client.post(reverse('api:login'), data={'email': 'user1mail@mail.ru',
                                                                'password': 'password12345'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_json = json.loads(response.content)

        # check refresh token
        refresh_token = RefreshToken.objects.get(refresh_token=response_json['refresh_token'])
        time_difference = (datetime.datetime.now() + config.REFRESH_TOKEN_LIFETIME) - refresh_token.expiry_time.replace(tzinfo=None)
        self.assertTrue(time_difference < datetime.timedelta(seconds=1))
        self.assertEqual(refresh_token.user, user)

        # check access token
        try:
            decoded_jwt = jwt.decode(response_json['access_token'], settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.exceptions.PyJWTError:
            self.fail('Incorrect JWT')

    def test_login_twice(self):
        User.objects.create_user('user1', 'user1mail@mail.ru', password='password12345')
        response = self.client.post(reverse('api:login'), data={'email': 'user1mail@mail.ru',
                                                                'password': 'password12345'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        do_post_request('api:login',
                        {'email': 'user1mail@mail.ru', 'password': 'password12345'},
                        status.HTTP_403_FORBIDDEN,
                        {'detail': 'User already logged!'})(self)


class RefreshTestCase(APITestCase):
    test_refresh_no_data = do_post_request('api:refresh',
                                           None,
                                           status.HTTP_400_BAD_REQUEST,
                                           {"refresh_token": ["This field is required."]})

    test_refresh_blank_token = do_post_request('api:refresh',
                                               {'refresh_token': ''},
                                               status.HTTP_400_BAD_REQUEST,
                                               {"refresh_token": ["This field may not be blank."]})

    test_refresh_invalid_token = do_post_request('api:refresh',
                                                 {'refresh_token': 'b1b2b842-6efe-453c-a354-429566823385'},
                                                 status.HTTP_200_OK,
                                                 {'detail': 'User logged out'})

    def test_refresh_valid_token(self):
        user = User.objects.create_user('user1', 'user1mail@mail.ru', password='password12345')
        refresh_token = RefreshToken.objects.create(refresh_token='b1b2b842-6efe-453c-a354-429566823385', user=user)

        response = self.client.post(reverse('api:refresh'),
                                    data={'refresh_token': 'b1b2b842-6efe-453c-a354-429566823385'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_json = json.loads(response.content)

        # check refresh token
        refresh_token = RefreshToken.objects.get(refresh_token=response_json['refresh_token'])
        time_difference = (datetime.datetime.now() + config.REFRESH_TOKEN_LIFETIME) - refresh_token.expiry_time.replace(
            tzinfo=None)
        self.assertTrue(time_difference < datetime.timedelta(seconds=1))
        self.assertEqual(refresh_token.user, user)

        # check access token
        try:
            decoded_jwt = jwt.decode(response_json['access_token'], settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.exceptions.PyJWTError:
            self.fail('Incorrect JWT')


class LogoutTestCase(APITestCase):
    test_logout_no_data = do_post_request('api:logout',
                                          None,
                                          status.HTTP_400_BAD_REQUEST,
                                          {"refresh_token": ["This field is required."]})

    test_logout_blank_token = do_post_request('api:logout',
                                              {'refresh_token': ''},
                                              status.HTTP_400_BAD_REQUEST,
                                              {"refresh_token": ["This field may not be blank."]})

    test_logout_invalid_token = do_post_request('api:logout',
                                                {'refresh_token': 'b1b2b842-6efe-453c-a354-429566823385'},
                                                status.HTTP_200_OK,
                                                {'detail': 'User not logged'})

    def test_logout_valid_token(self):
        user = User.objects.create_user('user1', 'user1mail@mail.ru', password='password12345')
        refresh_token = RefreshToken.objects.create(refresh_token='b1b2b842-6efe-453c-a354-429566823385', user=user)

        do_post_request('api:logout',
                        {'refresh_token': 'b1b2b842-6efe-453c-a354-429566823385'},
                        status.HTTP_200_OK,
                        {"success": "User logged out."})(self)


class PersonalInfoTestCase(APITestCase):
    test_get_personal_info_no_auth_header = do_get_request('api:me',
                                                           None,
                                                           status.HTTP_403_FORBIDDEN,
                                                           {"detail": 'Not authorized access'})


    test_get_personal_info_blank_auth_header = do_get_request('api:me',
                                                              {'Authorization': ''},
                                                              status.HTTP_403_FORBIDDEN,
                                                              {"detail": 'Not authorized access'})

    def test_get_personal_info_invalid_auth_header(self):
        do_get_request('api:me',
                       {'Authorization': 'sdfhgsvdhfgvhgvhvg'},
                       status.HTTP_403_FORBIDDEN,
                       {"detail": 'Not authorized access'})(self)

        do_get_request('api:me',
                       {'Authorization': 'Bearer sdfhgsvdhfgvhgvhvg'},
                       status.HTTP_403_FORBIDDEN,
                       {"detail": 'Cannot decode JWT!'})(self)

    test_get_personal_info_invalid_jwt = do_get_request('api:me',
                                                        {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'},
                                                        status.HTTP_403_FORBIDDEN,
                                                        {"detail": 'JWT Signature verification failed'})

    test_update_personal_info_no_auth_header = do_put_request('api:me',
                                                              None,
                                                              None,
                                                              status.HTTP_403_FORBIDDEN,
                                                              {"detail": 'Not authorized access'})

    test_update_personal_info_blank_auth_header = do_put_request('api:me',
                                                                 {'Authorization': ''},
                                                                 None,
                                                                 status.HTTP_403_FORBIDDEN,
                                                                 {"detail": 'Not authorized access'})

    def test_update_personal_info_invalid_auth_header(self):
        do_put_request('api:me',
                       {'Authorization': 'sdfhgsvdhfgvhgvhvg'},
                       None,
                       status.HTTP_403_FORBIDDEN,
                       {"detail": 'Not authorized access'})(self)

        do_put_request('api:me',
                       {'Authorization': 'Bearer sdfhgsvdhfgvhgvhvg'},
                       None,
                       status.HTTP_403_FORBIDDEN,
                       {"detail": 'Cannot decode JWT!'})(self)

    test_update_personal_info_invalid_jwt = do_put_request('api:me',
                                                           {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'},
                                                           None,
                                                           status.HTTP_403_FORBIDDEN,
                                                           {"detail": 'JWT Signature verification failed'})

