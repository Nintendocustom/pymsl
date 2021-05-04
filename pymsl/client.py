"""
This module serves as the core client that holds
the various functions needed for the E2E encrypted
API interaction for the Netflix MSL API
"""

import base64
import json
import os
import random
import re
import time
from datetime import datetime

import pymsl.utils
import requests
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Util import Padding
from pymsl.exceptions import (KeyExchangeError, LicenseError,
                              ManifestError, UserAuthDataError)

BASE_URL = 'https://www.netflix.com/nq/msl_v1/cadmium'

ENDPOINTS = {
    'manifest': BASE_URL + '/pbo_manifests/^1.0.0/router',
    'license': BASE_URL + "/pbo_licenses/^1.0.0/router",
}

VALID_AUTH_SCHEMES = [
    'EMAIL_PASSWORD',
    'EMAIL_PASSWORDHASH',
    'MDX',
    'NETFLIXID',
    'SSO',
    'USER_ID_TOKEN'
]

DEFAULTS = {
    #'esn': pymsl.utils.generate_esn('NFCDTS-01-'),
     'esn': pymsl.utils.generate_esn('NFCDCH-02-'),
    'drm_system': 'widevine',
    'profiles': [
        'playready-h264mpl30-dash',
        'playready-h264mpl31-dash',
        'playready-h264mpl40-dash',
        'playready-h264hpl30-dash',
        'playready-h264hpl31-dash',
        'playready-h264hpl40-dash',
        'heaac-2-dash',
        'dfxp-ls-sdh',
        'simplesdh',
        'nflx-cmisc',
        'BIF240',
        'BIF320'
    ],
    'languages': ['en-US'],
    'key_request_data': {
        'scheme': 'ASYMMETRIC_WRAPPED',
        'keydata': {
            'keypairid': 'rsaKeypairId',
            'mechanism': 'JWK_RSA'
        }
    },
    'extra_manifest_params': {}
}


class MslClient(object):
    def __init__(self, user_auth_data, **kwargs):
        if user_auth_data.get('scheme') not in VALID_AUTH_SCHEMES:
            raise UserAuthDataError('%s is not a valid user authentication scheme' % user_auth_data.get('scheme'))

        self.msl_session = {
            'user_auth_data': user_auth_data,
            'esn': kwargs.get('esn', DEFAULTS['esn']),
            'drm_system': kwargs.get('drm_system', DEFAULTS['drm_system']),
            'profiles': kwargs.get("profiles", DEFAULTS["profiles"]),
            'keypair': None,
            'message_id': kwargs.get('message_id', random.SystemRandom().randint(0, pow(2, 52))),
            'languages': kwargs.get('languages', DEFAULTS['languages']),
            'proxies': kwargs.get('proxies', None),
            'key_request_data': kwargs.get('key_request_data', DEFAULTS['key_request_data']),
            'extra_manifest_params': kwargs.get('extra_manifest_params', DEFAULTS['extra_manifest_params']),
            'license_path': None
        }
        self.header = {
            'sender': self.msl_session['esn'],
            'renewable': True,
            'capabilities': {
                'languages': self.msl_session['languages'],
                'compressionalgos': ['']
            },
            'messageid': self.msl_session['message_id'],
            'keyrequestdata': [self.msl_session['key_request_data']]}

    def login(self, path=None, rsa_key=None, msl_storage=None):
        """
        :param path: the path of the rsa key, msl_storage
        :type path: str
        :param rsa_key: filename of the rsa key
        :type rsa_key: str
        :param msl_storage: filename of the file that stores information about msl
        This function will help you to log in your Netflix account more easy and better.
        It will import your RSA key or create a RSA key. Additionally it will import important keys for later requests like the manifest or the license
        """

        # if self.file_exists(COOKIES_FOLDER, msl_storage1):
        if path is not None:
            os.makedirs(path, exist_ok=True)
            if rsa_key is None or msl_storage is None:
                raise NameError("rsa_key or msl_storage is not defined but path is")
            if self.__file_exists(path, msl_storage):
                pass
            elif self.__file_exists(path, rsa_key):
                # self.logger.info('old RSA key found, using')
                self.load_rsa_keys(path, rsa_key)  # just imports the rsa key
                self.msl_session['key_request_data']['keydata']['publickey'] = base64.b64encode(
                    self.msl_session['keypair'].publickey().exportKey('DER')).decode('utf8')
                self.msl_session['session_keys'] = self.__parse_handshake(self.__perform_key_handshake())
                # self.save_rsa_keys(path, rsa_key)
                self.save_msl_data(path, msl_storage)
                return

            else:
                # self.logger.info('create new RSA Keys')
                # Create new Key Pair and save
                self.msl_session["keypair"] = self.__generate_rsa_key()
                self.msl_session['key_request_data']['keydata']['publickey'] = base64.b64encode(
                    self.msl_session['keypair'].publickey().exportKey('DER')).decode('utf8')
                self.save_rsa_keys(path, rsa_key)
                self.msl_session['session_keys'] = self.__parse_handshake(self.__perform_key_handshake())
                self.save_msl_data(path, msl_storage)
                return

            self.load_msl_data(path, msl_storage)
            self.load_rsa_keys(path, rsa_key)
            return
        self.msl_session["keypair"] = self.__generate_rsa_key()
        self.msl_session['key_request_data']['keydata']['publickey'] = base64.b64encode(
            self.msl_session['keypair'].publickey().exportKey('DER')).decode('utf8')
        self.msl_session['session_keys'] = self.__parse_handshake(self.__perform_key_handshake())

    def get_metadata(self, viewable_id, build):  # todo finish this, maybe without build
        if self.msl_session["user_auth_data"].get("schem") != "NETFLIXID":
            raise UserAuthDataError("%s doesn't work with get_metadata, you need NETFLIXID")

    def load_manifest(self, viewable_id):
        """
        load_manifest()

        @param viewable_id: Int of viewable ID
                             to obtain manifest for

        @return: manifest (dict)

        This function performs a manifest request based on
        the parameters supplied when initializing the client
        object. If there are no errors, it will return the
        manifest as a dict. If there are errors, it will
        raise a ManifestError exception with the response
        from the MSL API as the body.
        """
        if not 'session_keys' in self.msl_session:
            raise ManifestError("You have to log in first")
        if not isinstance(viewable_id, int):
            raise TypeError('viewable_id must be of type int')

        manifest_request_data = {
            'version': 2,
            'url': '/manifest',
            'method': 'manifest',
            'id': 15429961728572,
            'esn': self.msl_session['esn'],
            'languages': self.msl_session['languages'],
            'uiVersion': 'shakti-v4bf615c3',
            'clientVersion': '6.0011.511.011',
            'params': {
                'type': 'standard',
                'viewableId': viewable_id,
                'profiles': self.msl_session['profiles'],
                'flavor': 'STANDARD',
                'drmType': self.msl_session['drm_system'],
                'drmVersion': 25,
                'usePsshBox': True,
                'isBranching': False,
                'useHttpsStreams': True,
                'imageSubtitleHeight': 720,
                'uiVersion': 'shakti-v4bf615c3',
                'clientVersion': '6.0011.511.011',
                'supportsPreReleasePin': True,
                'supportsWatermark': True,
                'showAllSubDubTracks': True,
                'videoOutputInfo': [
                    {
                        'type': 'DigitalVideoOutputDescriptor',
                        'outputType': 'unknown',
                        'supportedHdcpVersions': [1.4],
                        'isHdcpEngaged': True
                    }
                ],
                'preferAssistiveAudio': False,
                'isNonMember': False
            }
        }

        manifest_request_data['params'].update(
            self.msl_session['extra_manifest_params']
        )

        request_data = self.__generate_msl_request_data(manifest_request_data)
        while True:
            resp = requests.post(
                url=ENDPOINTS['manifest'],
                data=request_data,
                proxies=self.msl_session['proxies'],
                timeout=None
            )
            if resp.status_code != 408:
                break

        try:
            resp.json()
        except ValueError:
            manifest = self.__decrypt_msl_payload(resp.text)
            if manifest.get('result'):
                self.msl_session['license_path'] = manifest[
                    'result']['links']['license']['href']
                return manifest
            raise ManifestError(manifest)
        raise ManifestError(
            json.loads(base64.b64decode(
                resp.json()['errordata']
            ).decode('utf8'))['errormsg']
        )

    def get_license(self, challenge):
        """
        get_license()

        @param challenge:  EME license request as a byte string
                           that will be used to obtain a license

        @return: license (dict)

        This function performs a license request based on
        the parameters supplied when initalizing the client
        object. If there are no errors, it will return the
        licenses as a list of dicts. If there are errors, it will
        raise a LicenseError exception with the response
        from the MSL API as the body.
        """

        if not isinstance(challenge, bytes):
            raise TypeError('challenge must be of type bytes')

        if not self.msl_session['license_path']:
            raise LicenseError(
                'Manifest must be loaded before license is acquired'
            )

        license_request_data = {
            'version': 2,
            'url': self.msl_session['license_path'],
            'id': 15429961788811,
            'esn': self.msl_session['esn'],
            'languages': self.msl_session['languages'],
            'uiVersion': 'shakti-v25d2fa21',
            'clientVersion': '6.0011.511.011',
            'params': [{
                'sessionId': str(time.time()).replace('.', '')[0:-2],
                'clientTime': int(time.time()),
                'challengeBase64': base64.b64encode(challenge).decode('utf8'),
                'xid': str(int(time.time() * 10000) + 1610)
            }],
            'echo': 'sessionId'
        }

        request_data = self.__generate_msl_request_data(license_request_data)
        resp = requests.post(
            url=ENDPOINTS['license'],
            data=request_data,
            proxies=self.msl_session['proxies']
        )

        try:
            resp.json()
        except ValueError:
            msl_license_data = self.__decrypt_msl_payload(resp.text)
            if msl_license_data.get('result'):
                return msl_license_data
            raise LicenseError(msl_license_data)
        raise LicenseError(resp.text)

    def get_profiles(self):
        """
        :return: returns the profils
        This function returns the profiles used for the manifest request.
        """
        return self.msl_session["profiles"]

    def set_profiles(self, profiles):
        """
        :param profiles: list of profiles
        :return: Nothing
        This function can change the profils used in the manifest request.
        """
        if type(profiles) != list:
            raise TypeError("profiles most be type list")
        self.msl_session["profiles"] = profiles

    def set_esn(self, esn):
        self.msl_session["esn"] = esn
        self.header["sender"] = esn

    def __decrypt_msl_payload(self, payload):
        """
        decrypt_msl_payload()

        @param payload: Chunked payload response as received from MSL API

        @return: Decrypted and assembled payload as a dict
        """

        payloads = re.split(
            r',"signature":"[0-9A-Za-z/+=]+"}',
            payload.split('}}')[1]
        )

        payloads = [x + '}' for x in payloads][:-1]

        payload_chunks = payloads

        chunks = []
        for chunk in payload_chunks:
            payloadchunk = json.loads(chunk)
            encryption_envelope = payloadchunk['payload']
            cipher = AES.new(
                self.msl_session['session_keys']['encryption_key'],
                AES.MODE_CBC,
                base64.b64decode(json.loads(
                    base64.b64decode(encryption_envelope).decode('utf8')
                )['iv'])
            )

            plaintext = cipher.decrypt(
                base64.b64decode(json.loads(
                    base64.b64decode(encryption_envelope).decode('utf8')
                )['ciphertext'])
            )

            plaintext = json.loads(Padding.unpad(plaintext, 16).decode('utf8'))

            data = plaintext['data']
            data = base64.b64decode(data).decode('utf8')
            chunks.append(data)

        decrypted_payload = json.loads(''.join(chunks))

        return decrypted_payload

    def __generate_msl_request_data(self, data):
        """
        generate_msl_request_data()

        @param data: Data to wrap in encryption envelopes so it
                     can be sent to MSL API

        @return: Chunked payload and header of data
        """

        header = self.header.copy()
        header['userauthdata'] = self.msl_session['user_auth_data']

        header_envelope = pymsl.utils.msl_encrypt(
            self.msl_session, pymsl.utils.dumps(header)
        )

        header_signature = HMAC.new(
            self.msl_session['session_keys']['sign_key'],
            header_envelope, SHA256
        ).digest()

        enc_header = {
            'headerdata': base64.b64encode(header_envelope).decode('utf8'),
            'signature': base64.b64encode(header_signature).decode('utf8'),
            'mastertoken': self.msl_session['session_keys']['mastertoken'],
        }

        payload = {
            'messageid': self.msl_session['message_id'],
            'data': base64.b64encode(
                pymsl.utils.dumps(data).encode('utf8')
            ).decode('utf8'),
            'sequencenumber': 1,
            'endofmsg': True
        }

        payload_envelope = pymsl.utils.msl_encrypt(
            self.msl_session,
            pymsl.utils.dumps(payload)
        )

        payload_signature = HMAC.new(
            self.msl_session['session_keys']['sign_key'],
            payload_envelope,
            SHA256
        ).digest()

        payload_chunk = {
            'payload': base64.b64encode(payload_envelope).decode('utf8'),
            'signature': base64.b64encode(payload_signature).decode('utf8')
        }

        return pymsl.utils.dumps(enc_header) + pymsl.utils.dumps(payload_chunk)

    @staticmethod
    def __generate_rsa_key():
        """
        :return: RSA key
        """
        return RSA.generate(2048)

    def save_msl_data(self, path, filename):
        with open(os.path.join(path, filename), "w") as f:
            msl_storage = {
                "encryption_key": base64.b64encode(self.msl_session["session_keys"]["encryption_key"]).decode("utf8"),
                "sign_key": base64.b64encode(self.msl_session["session_keys"]["sign_key"]).decode("utf8"),
                "tokens": {
                    "mastertoken": self.msl_session["session_keys"]["mastertoken"]
                }
            }
            f.write(json.dumps(msl_storage))

    def load_rsa_keys(self, path, filename):
        loaded_key = self.__load_file(path, filename)
        self.msl_session["keypair"] = RSA.importKey(loaded_key)
        self.msl_session['key_request_data']['keydata']['publickey'] = base64.b64encode(
            self.msl_session['keypair'].publickey().exportKey('DER')).decode('utf8')

    def save_rsa_keys(self, path, filename):
        if self.msl_session["keypair"] is None:
            return "error"
        # self.logger.debug('Save RSA Keys')
        # Get the DER Base64 of the keys
        encrypted_key = self.msl_session["keypair"].exportKey()
        self.__save_file(path, filename, encrypted_key)

    def __parse_handshake(self, response):
        """
        parse_handshake()

        @param response: Key exchange response as a dict

        @return: Parsed key exchange dict containing mastertoken,
                 sequence number, encryption key, and sign key
        """

        if response.get('errordata'):
            raise KeyExchangeError(
                base64.b64decode(response['errordata']).decode('utf8')
            )

        headerdata = json.loads(
            base64.b64decode(response['headerdata']).decode('utf8')
        )

        mastertoken = headerdata['keyresponsedata']['mastertoken']
        sequence_number = json.loads(
            base64.b64decode(mastertoken['tokendata']).decode('utf8')
        )['sequencenumber']

        encrypted_encryption_key = base64.b64decode(
            headerdata['keyresponsedata']['keydata']['encryptionkey']
        )

        encrypted_sign_key = base64.b64decode(
            headerdata['keyresponsedata']['keydata']['hmackey']
        )

        oaep_cipher = PKCS1_OAEP.new(self.msl_session['keypair'])
        encryption_key_data = json.loads(
            oaep_cipher.decrypt(encrypted_encryption_key).decode('utf8')
        )

        encryption_key = pymsl.utils.webcrypto_b64decode(
            encryption_key_data['k']
        )

        sign_key_data = json.loads(
            oaep_cipher.decrypt(encrypted_sign_key).decode('utf8')
        )

        sign_key = pymsl.utils.webcrypto_b64decode(sign_key_data['k'])

        return {
            'mastertoken': mastertoken,
            'sequence_number': sequence_number,
            'encryption_key': encryption_key,
            'sign_key': sign_key
        }

    def __perform_key_handshake(self):
        """
        perform_key_handshake()

        @return: Key handshake response as a dict

        This function performs the inital key handshake
        based on parameters supplied on class initialization
        and returns the response as a dict
        """

        header = {
            'entityauthdata': {
                'scheme': 'NONE',
                'authdata': {
                    'identity': self.msl_session['esn'],
                }
            },
            'signature': ''}
        header['headerdata'] = base64.b64encode(
            pymsl.utils.dumps(self.header).encode('utf8')
        ).decode('utf8')

        payload = {
            'signature': ''
        }

        payload['payload'] = base64.b64encode(pymsl.utils.dumps({
            'sequencenumber': 1,
            'messageid': self.msl_session['message_id'],
            'endofmsg': True,
            'data': ''
        }).encode('utf8')).decode('utf8')

        request = pymsl.utils.dumps(header) + pymsl.utils.dumps(payload)
        resp = requests.post(
            url=ENDPOINTS['manifest'],
            data=request,
            proxies=self.msl_session['proxies']
        )

        return resp.json()

    def load_msl_data(self, path, storage_name, rsa_key="rsa.bin"):
        msl_data = json.JSONDecoder().decode(self.__load_file(path, storage_name).decode("utf-8"))

        master_token = json.JSONDecoder().decode(
            base64.b64decode(msl_data["tokens"]["mastertoken"]['tokendata']).decode('utf-8'))

        valid_util = datetime.utcfromtimestamp(int(master_token['expiration']))
        present = datetime.now()
        difference = valid_util - present
        difference = difference.total_seconds() / 60 / 60

        if difference < 10:
            self.load_rsa_keys(path, rsa_key)
            self.msl_session['session_keys'] = self.__parse_handshake(self.__perform_key_handshake())
            return

        self.msl_session["session_keys"] = self.__import_msl(msl_data)

    @staticmethod
    def __import_msl(msl_data):
        return {
            'mastertoken': msl_data['tokens']['mastertoken'],
            'sequence_number': json.JSONDecoder().decode(
                base64.standard_b64decode(msl_data["tokens"]["mastertoken"]['tokendata']).decode('utf-8'))[
                'sequencenumber'],
            'encryption_key': base64.standard_b64decode(msl_data['encryption_key']),
            'sign_key': base64.standard_b64decode(msl_data['sign_key'])
        }

    @staticmethod
    def __load_file(msl_data_path, filename):
        """
        Loads the content of a given filename
        :param filename: The file to load
        :return: The content of the file
        """
        with open(os.path.join(msl_data_path, filename), 'rb') as file_:
            file_content = file_.read()
            file_.close()
        return file_content

    @staticmethod
    def __save_file(msl_data_path, filename, content):
        """
        Saves the given content under given filename
        :param filename: The filename
        :param content: The content of the file
        """
        with open(os.path.join(msl_data_path, filename), 'wb') as file_:
            file_.write(content)
            file_.flush()
            file_.close()

    @staticmethod
    def __file_exists(path, file):
        return os.path.isfile(os.path.join(path, file))
    
    def __repr__(self):
        return '<MslClient %s>' % self.msl_session['message_id']
    