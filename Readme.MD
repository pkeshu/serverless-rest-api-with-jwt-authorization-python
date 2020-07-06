I'm putting this here for the next person like me that looks for it.

What I needed was:

A Private key that i can keep place behind a service (think AWS API GATEWAY) and generate JWT tokens securely and pass them down to lower services.
A Public key that i can give to any of my micro services/anything else that can validate that the JWT token is valid WITHOUT knowing my Private key
Setup:

  # lets create a key to sign these tokens with
  openssl genpkey -out mykey.pem -algorithm rsa -pkeyopt rsa_keygen_bits:2048 
  # lets generate a public key for it...
  openssl rsa -in mykey.pem -out mykey.pub -pubout 
  # make another key so we can test that we cannot decode from it
  openssl genpkey -out notmykey.pem -algorithm rsa -pkeyopt rsa_keygen_bits:2048 
  # this is really the key we would be using to try to check the signature
  openssl rsa -in notmykey.pem -out notmykey.pub -pubout
Code:

import jwt

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Load the key we created
with open("mykey.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# The data we're trying to pass along from place to place
data = {'user_id': 1}

# Lets create the JWT token -- this is a byte array, meant to be sent as an HTTP header
jwt_token = jwt.encode(data, key=private_key, algorithm='RS256')

print(f'data {data}')
print(f'jwt_token {jwt_token}')

# Load the public key to run another test...
with open("mykey.pub", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# This will prove that the derived public-from-private key is valid
print(f'decoded with public key (internal): {jwt.decode(jwt_token, private_key.public_key())}')
# This will prove that an external service consuming this JWT token can trust the token 
# because this is the only key it will have to validate the token.
print(f'decoded with public key (external): {jwt.decode(jwt_token, public_key)}')

# Lets load another public key to see if we can load the data successfuly