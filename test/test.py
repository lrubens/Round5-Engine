import OpenSSL
from OpenSSL._util import (
    ffi as _ffi,
    lib as _lib)
from OpenSSL import crypto


def create_self_signed_cert():
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "UK"
    cert.get_subject().ST = "London"
    cert.get_subject().L = "London"
    cert.get_subject().O = "Dummy Company Ltd"
    cert.get_subject().OU = "Dummy Company Ltd"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    open("CERT_FILE.crt", "wt").write(
        bytes.decode(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)))
    open("KEY_FILE.key", "wt").write(
        bytes.decode(crypto.dump_privatekey(crypto.FILETYPE_PEM, k)))


def init_ssl_engine(engine):
    if not engine:
        raise ValueError('Environment variable SSL_ENGINE is not set')

    if isinstance(engine, str):
        engine = engine.encode('utf-8')

    engineId = _ffi.new("const char[]", engine)

    # Reference: https://www.openssl.org/docs/man1.0.2/crypto/engine.html
    _lib.ENGINE_load_builtin_engines()
    e = _lib.ENGINE_by_id(engineId)

    if e == _ffi.NULL:
        raise ValueError('Cannot find engine {}'.format(
            engine.decode('utf-8')))

    if not _lib.ENGINE_init(e):
        _lib.ENGINE_free(e)
        raise Exception('Cannot initialize engine {}'.format(
            engine.decode('utf-8')))

    if not _lib.ENGINE_set_default_RSA(e):
        _lib.ENGINE_free(e)
        raise ValueError('Cannot set engine {} as default RSA'.format(
            engine.decode('utf-8')))

    print('Engine {} is ready to use: {}'.format(engine.decode(), e))


def main():
    init_ssl_engine('round5')
    create_self_signed_cert()


main()
