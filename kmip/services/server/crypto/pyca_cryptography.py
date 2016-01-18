# Copyright (c) 2016 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging
import os

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives.ciphers import algorithms

from kmip.core import enums
from kmip.core import exceptions
from kmip.services.server.crypto import api


class CryptographyEngine(api.CryptographicEngine):
    """
    A cryptographic engine that uses pyca/cryptography to generate
    cryptographic objects and conduct cryptographic operations.
    """

    def __init__(self):
        """
        Construct a CryptographyEngine.
        """
        self._symmetric_key_algorithms = {
            enums.CryptographicAlgorithm.TRIPLE_DES: algorithms.TripleDES,
            enums.CryptographicAlgorithm.AES: algorithms.AES,
            enums.CryptographicAlgorithm.BLOWFISH: algorithms.Blowfish,
            enums.CryptographicAlgorithm.CAMELLIA: algorithms.Camellia,
            enums.CryptographicAlgorithm.CAST5: algorithms.CAST5,
            enums.CryptographicAlgorithm.IDEA: algorithms.IDEA,
            enums.CryptographicAlgorithm.RC4: algorithms.ARC4
        }
        self._asymetric_key_algorithms = {
            enums.CryptographicAlgorithm.RSA: self._create_rsa_key_pair,
            enums.CryptographicAlgorithm.DSA: self._create_dsa_key_pair
        }

    def create_symmetric_key(self, algorithm, length):
        """
        Create a symmetric key.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration specifying the
                algorithm for which the created key will be compliant.
            length(int): The length of the key to be created. This value must
                be compliant with the constraints of the provided algorithm.

        Returns:
            dict: A dictionary containing the key data, with the following
                key/value fields:
                * value - the bytes of the key
                * format - a KeyFormatType enumeration for the bytes format

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                length is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.
        """
        if algorithm not in self._symmetric_key_algorithms.keys():
            raise exceptions.InvalidField(
                "The cryptographic algorithm {0} is not a supported symmetric "
                "key algorithm.".format(algorithm)
            )

        cryptography_algorithm = self._symmetric_key_algorithms.get(algorithm)

        if length not in cryptography_algorithm.key_sizes:
            raise exceptions.InvalidField(
                "The cryptographic length ({0}) is not valid for "
                "the cryptographic algorithm ({1}).".format(length, algorithm.name)
            )

        logging.info("Generating a {0} symmetric key with length: {1}".format(
            algorithm.name, length)
        )

        key_bytes = os.urandom(length / 8)
        try:
            cryptography_algorithm(key_bytes)
        except Exception as e:
            logging.exception(e)
            raise exceptions.CryptographicFailure(
                "Invalid bytes for the provided cryptographic algorithm.")

        return {'value': key_bytes, 'format': enums.KeyFormatType.RAW}

    def create_asymmetric_key_pair(self, algorithm, length):
        """
        Create an asymmetric key pair.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration specifying the
                algorithm for which the created keys will be compliant.
            length(int): The length of the keys to be created. This value must
                be compliant with the constraints of the provided algorithm.

        Returns:
            dict: A dictionary containing the public key data, with the
                following key/value fields:
                * value - the bytes of the key
                * format - a KeyFormatType enumeration for the bytes format
            dict: A dictionary containing the private key data, identical in
                structure to the one above.

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                length is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.
        """
        if algorithm not in self._asymetric_key_algorithms.keys():
            raise exceptions.InvalidField(
                "The cryptographic algorithm ({0}) is not a supported "
                "asymmetric key algorithm.".format(algorithm)
            )

        engine_method = self._asymetric_key_algorithms.get(algorithm)
        return engine_method(length)

        # OPEN QUESTIONS
        # Do I need the following items as arguments to this method?
        # * the public exponent value for RSA (default to 65537?)
        # * the public_bytes encoding value for RSA (default ?)
        # * the public_bytes format value for RSA (default ?)
        # * the private_bytes encoding value for RSA (default ?)
        # * the private_bytes format value for RSA (default ?)
        # * the private_bytes encryption scheme for RSA (default ?)

    def _create_rsa_key_pair(self, length, public_exponent=65537):
        logging.info("Generating an RSA key pair with length: {0}, and "
                     "public_exponent: {1}".format(length, public_exponent))
        try:
            private_key = rsa.generate_private_key(
                public_exponent=public_exponent,
                key_size=length,
                backend=default_backend())
            public_key = private_key.public_key()

            private_bytes = private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            public_bytes = public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.PKCS1)
        except Exception as e:
            logging.exception(e)
            raise exceptions.CryptographicFailure(
                "An error occurred while generating the RSA key pair. "
                "See the server log for more information."
            )

        public_key = {
            'value': public_bytes,
            'format': enums.KeyFormatType.PKCS_1
        }
        private_key = {
            'value': private_bytes,
            'format': enums.KeyFormatType.PKCS_8
        }

        return public_key, private_key

    def _create_dsa_key_pair(self, length):
        logging.info("Generating a DSA key pair with length: {0}".format(
            length))
        try:
            private_key = dsa.generate_private_key(
                key_size=length,
                backend=default_backend())
            public_key = private_key.public_key()

            private_bytes = private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            public_bytes = public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
        except Exception as e:
            logging.exception(e)
            raise exceptions.CryptographicFailure(
                "An error occurred while generating the DSA key pair. "
                "See the server log for more information."
            )

        public_key = {
            'value': public_bytes,
            'format': enums.KeyFormatType.X_509
        }
        private_key = {
            'value': private_bytes,
            'format': enums.KeyFormatType.PKCS_8
        }

        return public_key, private_key
