from unittest import TestCase, main

from loauth import LocalBoxRequestValidator
from loauth import ClientStub
from oauthlib.common import Request


class TestLocalBoxRequestValidator(TestCase):

    def setUp(self):
        self.validator = LocalBoxRequestValidator()

    def test_validate_client_id(self):
        self.assertTrue(self.validator.validate_client_id('10', None))

    def test_validate_response_type(self):
        for good_item in 'code', 'token':
            self.assertTrue(
                self.validator.validate_response_type(
                    None,
                    good_item,
                    None,
                    None))
        for bad_item in 'codes', 'toke', '', 'pony', '':
            self.assertFalse(
                self.validator.validate_response_type(
                    None,
                    bad_item,
                    None,
                    None))

    def test_validate_user(self):
        self.assertTrue(
            self.validator.validate_user(
                'user',
                'pass',
                ClientStub('10'),
                None))
        self.assertFalse(
            self.validator.validate_user(
                'user',
                'pas2',
                ClientStub('10'),
                None))
        self.assertFalse(
            self.validator.validate_user(
                'use2',
                'pass',
                ClientStub('10'),
                None))
        self.assertFalse(
            self.validator.validate_user(
                'use2',
                'pas2',
                ClientStub('10'),
                None))

    def test_authenticate_client(self):
        request = Request('http://localhost/authenticate_client',
                          'GET',
                          None,
                          {'client_id': '10',
                           'client_secret': 'secret'})
        self.assertTrue(self.validator.authenticate_client(request))
        request = Request('http://localhost/authenticate_client',
                          'GET',
                          None,
                          {'client_id': '10',
                           'client_secret': 'secre'})
        self.assertFalse(self.validator.authenticate_client(request))
        request = Request('http://localhost/authenticate_client',
                          'GET',
                          None,
                          {'client_id': '1',
                           'client_secret': 'secret'})
        self.assertFalse(self.validator.authenticate_client(request))


if __name__ == '__main__':
    main()
