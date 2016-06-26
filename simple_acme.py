import base64
import binascii
import config as cfg
import copy
import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
import textwrap
from urllib2 import urlopen

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger("Simple-ACME")
logger.setLevel(logging.INFO)


LE_NONCE = None


# from: https://github.com/diafygi/acme-tiny
# helper function base64 encode for jose spec
def _b64(b):
    return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")


# helper functions for making (un)signed requests
def _get_request(url):
    try:
        resp = urlopen(url)
        return resp.getcode(), resp.read(), resp.info()
    except IOError as e:
        return e.getcode(), e.read(), e.info()


def _send_signed_request(user, url, payload):
    global LE_NONCE
    payload64 = _b64(json.dumps(payload).encode('utf8'))
    protected = copy.deepcopy(user.jws_header)

    # Get a Nonce if we don't have one
    if LE_NONCE is None:
        LE_NONCE = urlopen(cfg.DIRECTORY_URL + "/directory").headers['Replay-Nonce']
    protected["nonce"] = LE_NONCE
    LE_NONCE = None  # Make sure we don't re-use a nonce

    protected64 = _b64(json.dumps(protected).encode('utf8'))
    signature = user.sign("{0}.{1}".format(protected64, payload64))
    data = json.dumps({
        "header": user.jws_header, "protected": protected64,
        "payload": payload64, "signature": _b64(signature),
    })
    try:
        resp = urlopen(url, data.encode('utf8'))
        LE_NONCE = resp.info().getheader('Replay-Nonce', None)
        return resp.getcode(), resp.read(), resp.info()
    except IOError as e:
        LE_NONCE = e.info().getheader('Replay-Nonce', None)
        raise IOError("Unexpected response: {}".format(e.read()))


class AcmeUser:
    def serialize(self):
        d = {
            'key': self.key,
            'keybits': self.keybits,
            'url': self.url,
            'agreement': self.agreement
        }
        return json.dumps(d)

    @staticmethod
    def unserialize(data):
        data = json.loads(data)
        u = AcmeUser(
            keybits=data['keybits'],
            key=data['key'],
            url=data['url'],
            agreement=data['agreement'])
        u._init_keydata()
        return u

    def __init__(self, keybits=2048, key=None, url=None, agreement=None):
        self.keybits = keybits
        self.key = key
        self.url = url
        self.agreement = agreement
        self._keydata_loaded = False

    def create_key(self):
        proc = subprocess.Popen(["openssl", "genrsa", str(self.keybits)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        logger.debug("Stdout: ".format(out))
        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        self.key = out

    def _init_keydata(self):
        # parse account key to get public key
        proc = subprocess.Popen(["openssl", "rsa", "-in", "/dev/stdin", "-noout", "-text"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(self.key)
        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        pub_hex, pub_exp = re.search(
            r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
            out.decode('utf8'), re.MULTILINE | re.DOTALL).groups()
        pub_exp = "{0:x}".format(int(pub_exp))
        pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
        self.pub_exp = pub_exp
        self.pub_hex = pub_hex
        self._keydata_loaded = True

    @property
    def pub_exp(self):
        if not self._keydata_loaded:
            self._init_keydata()
        return self.pub_exp

    @property
    def pub_hex(self):
        if not self._keydata_loaded:
            self._init_keydata()
        return self.pub_hex

    @property
    def jws_header(self):
        # Build the JWS header needed to sign requests
        jws_header = {
            "alg": "RS256",
            "jwk": {
                "e": _b64(binascii.unhexlify(self.pub_exp)),
                "kty": "RSA",
                "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", self.pub_hex))),
            },
        }

        return jws_header

    @property
    def thumbprint(self):
        # thumbprint is used for validating challenges
        accountkey_json = json.dumps(self.jws_header['jwk'], sort_keys=True, separators=(',', ':'))
        return _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    def refresh_registration(self):
        # refresh registration details(and agreement if necessary)
        code, result, info = _send_signed_request(
            self, self.url, {
                "resource": "reg",
                "agreement": self.agreement,
            }
        )

        # if the agreement has changed, autoaccept it and refresh the registration again
        links = info.getheader('Link')
        if re.search(r';rel="terms-of-service"', links):
            new_agreement = re.sub(r'.*<(.*)>;rel="terms-of-service".*', r'\1', links)
        if self.agreement != new_agreement:
            self.agreement = new_agreement
            self.refresh_registration()

    def register(self, email):
        if not self.url:
            code, result, info = _send_signed_request(
                self,
                cfg.DIRECTORY_URL + "/acme/new-reg",
                {
                    "resource": "new-reg",
                    "contact": [
                        "mailto:{}".format(email)
                    ],
                })
            self.url = info.getheader('Location')
            links = info.getheader('Link')
            if re.search(r';rel="terms-of-service"', links):
                self.agreement = re.sub(r'.*<(.*)>;rel="terms-of-service".*', r'\1', links)

        self.refresh_registration()

    def sign(self, data):
        # write key to tmp file
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(self.key)
        f.close()

        # sign the data
        proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", f.name],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        signature, err = proc.communicate(data.encode('utf8'))

        # delete temp key file
        # TODO: maybe overwrite this?
        os.unlink(f.name)

        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return signature


class AcmeAuthorization:
    @staticmethod
    def unserialize(user, data):
        data = json.loads(data)
        authzr = AcmeAuthorization(
            user=user,
            domain=data['domain'],
            url=data['url']
        )
        return authzr

    def serialize(self):
        return json.dumps({
            'domain': self.domain,
            'url': self.url
        })

    def __init__(self, user, domain, url=None):
        self.user = user
        self.domain = domain
        self.url = url
        self.challenges = []

    def authorize(self):
        if not self.url:
            code, result, info = _send_signed_request(
                self.user,
                cfg.DIRECTORY_URL + "/acme/new-authz",
                {
                    "resource": "new-authz",
                    "identifier": {
                        "type": "dns",
                        "value": self.domain
                    }
                })
            # save the url of this authorization so we can check it later
            self.url = info.getheader("Location")

        # get the data from our url
        code, result, info = _get_request(self.url)
        result = json.loads(result.decode('utf-8'))
        status = result['status']

        if status == 'pending':
            self.challenges = result['challenges']
        elif status == 'invalid':
            self.url = None
            # print out any error messages
            for c in result['challenges']:
                if 'error' in c:
                    logger.debug(c['error']['detail'])
        return status

    def complete_challenges(self, challenge_type, func_challenge, func_verifier):
        """ calls func_challenge to complete any challenges matching the desired type """
        challenges = [x for x in self.challenges if x['type'] == challenge_type]
        for challenge in challenges:
            token = challenge['token']
            key_authorization = "{}.{}".format(token, self.user.thumbprint)

            # DNS validation uses a different value for validation
            if challenge_type == 'dns-01':
                hashed_keyauth = hashlib.sha256(key_authorization.encode("utf-8")).digest()
                hashed_keyauth = base64.urlsafe_b64encode(hashed_keyauth).decode('utf8').replace("=", "")
                ret = func_challenge(self.domain, token, hashed_keyauth)
            else:
                ret = func_challenge(self.domain, token, key_authorization)

            if not ret:
                logger.debug("Challenge completion handler failed...")
                continue

            # try to verify/validate it
            ret = func_verifier(self.domain, token, key_authorization)
            if not ret:
                logger.warn("Error checking validation for {}. Trying anyway.".format(self.domain))

            # tell letsencrypt we finished the challenge
            code, result, info = _send_signed_request(
                self.user,
                challenge['uri'],
                {
                    "resource": "challenge",
                    "keyAuthorization": key_authorization
                })
            result = json.loads(result)


class AcmeCert:
    @staticmethod
    def _generate_private_key(keybits):
        proc = subprocess.Popen(["openssl", "genrsa", str(keybits)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        logger.debug("Stdout: ".format(out))
        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out

    @staticmethod
    def generate_csr(keybits, domains):
        # first create a private key
        pkey = AcmeCert._generate_private_key(keybits)

        # construct the list of SANs to go in the config file
        san_str = ""
        for i, domain in enumerate(domains, start=1):
            san_str += "DNS.{} = {}\n".format(i, domain)

        # create temporary openssl conf file
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write("""# openssl config file
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
countryName = US
stateOrProvinceName = NA
localityName = NA
organizationalUnitName = NA
commonName = {}
emailAddress = NA

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
{}""".format(domains[0], san_str))
        f.close()

        # now make the csr
        proc = subprocess.Popen(["openssl", "req", "-sha256", "-subj", "/", "-new", "-outform", "DER", "-key", "/dev/stdin", "-config", f.name],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(pkey)
        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        csr = out
        os.unlink(f.name)

        with open("csr_test.der", "wb") as csr_f:
            csr_f.write(csr)

        return pkey, csr

    @staticmethod
    def get_cert(user, csr_der):
        code, result, info = _send_signed_request(
            user,
            cfg.DIRECTORY_URL + "/acme/new-cert",
            {
                "resource": "new-cert",
                "csr": _b64(csr_der),
            })
        cert = None
        cert_chain = None

        cert = "-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n".format(
               "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64)))

        links = info.getheader('Link')
        if re.search(r';rel="up"', links):
            chain_cert_url = re.sub(r'.*<(.*)>;rel="up".*', r'\1', links)
            code, result, info = _get_request(chain_cert_url)
            proc = subprocess.Popen(["openssl", "x509", "-in", "/dev/stdin", "-inform", "DER", "-outform", "PEM"],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            cert_chain, err = proc.communicate(result)
            if proc.returncode != 0:
                raise IOError("OpenSSL Error: {0}".format(err))

        return cert, cert_chain
