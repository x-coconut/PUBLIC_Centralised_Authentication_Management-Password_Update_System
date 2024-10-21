# Copyright 2024 @x-coconut
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import http.server
import socketserver
from cryptography.hazmat.primitives.asymmetric import ec # elliptical curve for encryption
from cryptography.hazmat.primitives import serialization
from ecies.utils import generate_key
import base64


PORT = 5000

# send response
class ECCKeyRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):

            response = generate_ecc_keys()

            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))
            
            print("------------------------------")


def generate_ecc_keys():

    # generate public and private key
    keys = generate_key()
    private_bytes = keys.secret
    public_bytes = keys.public_key.format(True)

    private_key = ec.derive_private_key(int.from_bytes(private_bytes, byteorder='big'), ec.SECP256K1())
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_bytes)


    # Convert the private key to PEM format
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Save private key to file
    contents = (priv_pem.decode('utf-8'))
    file = open("ECC_private_key.txt", 'w')
    file.write(contents)
    file.close()


    # Convert the public key to DER format
    pub_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Base64 encode the public key DER
    pub_base64 = base64.b64encode(pub_der).decode('utf-8')

    return pub_base64

def main():
    with socketserver.TCPServer(("", PORT), ECCKeyRequestHandler) as httpd:
        print(f"Serving on port {PORT}. To exit press CTRL+C\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nInterrupted")
            httpd.server_close()



if __name__ == "__main__":
    main()
