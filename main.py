from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, InvalidTag


from nacl.signing import VerifyKey 
from nacl.exceptions import BadSignatureError

import argparse
#import ed25519
import base64
import json
import sys
import os

parser = argparse.ArgumentParser()

parser.add_argument('-p', '--path', dest='path', required=True, help='Path to license file (required)')
parser.add_argument('-l', '--license', dest='license', required=True, help='License key (required)')

args = parser.parse_args()

# Read the license file
license_file = None

try:
  with open(args.path) as f:
    license_file = f.read()
except (FileNotFoundError, PermissionError):
  print('[error] path does not exist! (or permission was denied)')

  sys.exit(1)

# Strip the header and footer from the license file certificate
payload = license_file.lstrip('-----BEGIN LICENSE FILE-----\n') \
                      .rstrip('-----END LICENSE FILE-----\n')

# Decode the payload and parse the JSON object
data = json.loads(base64.b64decode(payload))

# Retrieve the enc and sig properties
enc = data['enc']
sig = data['sig']
alg = data['alg']

if alg != 'aes-256-gcm+ed25519':
  print('[error] algorithm is not supported!')

  sys.exit(1)

# Verify using Ed25519
try:
  verify_key = VerifyKey(
    bytes.fromhex(os.environ['KEYGEN_PUBLIC_KEY'])
  )

  verify_key.verify(
    ('license/%s' % enc).encode(),
    base64.b64decode(sig),
  )
except (AssertionError, BadSignatureError):
  print('[error] verification failed!')

  sys.exit(1)

print('[info] verification successful!')

# Hash the license key using SHA256
digest = hashes.Hash(hashes.SHA256(), default_backend())
digest.update(args.license.encode())
key = digest.finalize()

# Split and decode the enc value
ciphertext, iv, tag = map(
  lambda p: base64.b64decode(p),
  enc.split('.'),
)

# Decrypt ciphertext
try:
  aes = Cipher(
    algorithms.AES(key),
    modes.GCM(iv, None, len(tag)),
    default_backend(),
  )
  dec = aes.decryptor()

  plaintext = dec.update(ciphertext) + \
              dec.finalize_with_tag(tag)
except (InvalidKey, InvalidTag):
  print('[error] decryption failed!')

  sys.exit(1)

print('[info] decryption successful!')
print(
  json.dumps(json.loads(plaintext.decode()), indent=2)
)
