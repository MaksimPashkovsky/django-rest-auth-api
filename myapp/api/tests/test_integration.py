import json
import time
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APITestCase
from .test_unit import do_post_request, do_get_request, do_put_request
from rest_framework import status


class FunctionalTest(APITestCase):
    def test_authorization(self):
        # 0 users
        self.assertEqual(User.objects.all().count(), 0)

        # registration
        do_post_request('api:register',
                        {'email': 'user12@gmail.com', 'password': 'password1234567890'},
                        status.HTTP_201_CREATED,
                        {"id": 1, "email": "user12@gmail.com"})(self)

        self.assertEqual(User.objects.all().count(), 1)

        # authorization
        response = self.client.post(reverse('api:login'), data={'email': 'user12@gmail.com', 'password': 'password1234567890'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # retrieving access and refresh tokens
        content = json.loads(response.content.decode('utf-8'))
        access_token, refresh_token = content['access_token'], content['refresh_token']

        # getting personal info
        do_get_request('api:me',
                       {'Authorization': f'Bearer {access_token}'},
                       status.HTTP_200_OK,
                       {'id': 1, 'email': "user12@gmail.com", 'username': 'user12'})(self)

        # updating personal info
        do_put_request('api:me',
                       {'Authorization': f'Bearer {access_token}'},
                       {'username': 'John Smith'},
                       status.HTTP_200_OK,
                       {'id': 1, 'email': "user12@gmail.com", 'username': 'John Smith'})(self)
        time.sleep(3)
        # refresh tokens
        response = self.client.post(reverse('api:refresh'), data={'refresh_token': refresh_token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # retrieving new access and refresh tokens
        content = json.loads(response.content.decode('utf-8'))
        new_access_token, new_refresh_token = content['access_token'], content['refresh_token']

        self.assertNotEqual(access_token, new_access_token)
        self.assertNotEqual(refresh_token, new_refresh_token)

        # getting personal info
        do_get_request('api:me',
                       {'Authorization': f'Bearer {new_access_token}'},
                       status.HTTP_200_OK,
                       {'id': 1, 'email': "user12@gmail.com", 'username': 'John Smith'})(self)

        # logging out
        do_post_request('api:logout',
                        {'refresh_token': new_refresh_token},
                        status.HTTP_200_OK,
                        {"success": "User logged out."})

