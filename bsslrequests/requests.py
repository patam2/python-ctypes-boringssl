import boringssl
from dataclasses import dataclass
from httpcore import NetworkStream


@dataclass
class SSLobject:
    selected_alpn_protocol: str = None


BoringSSL = boringssl.BoringSSL(
    boringssl_dll = r"", #modified
    crypto_dll= r"",
)

class BoringSSLNetworkStream(NetworkStream,):
    def __init__(self, ssl_p, ctx_p) -> None:
        self._ssl_ptr = ssl_p
        self._ctx_ptr = ctx_p

    def read(self, max_bytes: int, timeout: float = None) -> bytes:
        buf = b'\0' * max_bytes
        bytes_read = BoringSSL.SSL_READ(self._ssl_ptr, buf, max_bytes)
        print('SSL_READ, bytes read:', bytes_read)
        return buf[:bytes_read]
    
    def write(self, buffer, timeout = None):
        if not buffer:
            return
        while buffer:
            bytes_written = BoringSSL.SSL_WRITE(self._ssl_ptr, buffer, len(buffer))
            print('SSL_WRITE, bytes written:', bytes_written)

            buffer = buffer[bytes_written:]
    
    def close(self):
        pass

    def get_extra_info(self, info):
        if info == 'ssl_object':
            vers = BoringSSL.SSL_get0_alpn_selected(self._ssl_ptr)
            return SSLobject(selected_alpn_protocol=lambda: vers.decode('ascii'))
        else:
            print('requested info:', info)

    def start_tls(self, ssl_context, server_hostname: str | None = None, timeout: float | None = None) -> NetworkStream:
        BoringSSL.SSL_set_tlsext_host_name(self._ssl_ptr, server_hostname.encode('ascii'))
        #BoringSSL.SSL_CTX_add_cert_compression_alg(self._ctx_ptr, 2)
        BoringSSL.SSL_CONNECT(self._ssl_ptr)
        BoringSSL.SSL_do_handshake(self._ssl_ptr)
        return self


class BoringSSLBackend():
    def __init__(self):
        pass

    def connect_tcp(self, host, port, timeout, local_address, socket_options=None):
        ctx_p = BoringSSL.SSL_CTX_NEW(BoringSSL.TLS_method())
        BoringSSL.SSL_CTX_set_min_proto_version(ctx_p, 0x0303)
        sigalgs = [0x0403, 0x0804, 0x0401, 0x0503,0x0805, 0x0501, 0x0806, 0x0601]
        # http2: \x02h2
        # http1/1: \x08http/1.1
        # both: \x02h2\x08http/1.1
        alpn = b'\x02h2'
        BoringSSL.SSL_CTX_set_alpn_protos(ctx_p, alpn, len(alpn))

        ssl_p = BoringSSL.SSL_NEW(ctx_p)

        BoringSSL.SSL_enable_ocsp_stapling(ssl_p)
        BoringSSL.SSL_enable_signed_cert_timestamps(ssl_p)
        BoringSSL.SSL_set_signing_algorithm_prefs(ssl_p, sigalgs, len(sigalgs))

        BoringSSL.SSL_CTX_set_strict_cipher_list(ctx_p, b'ALL:!aPSK:!ECDSA+SHA1:!3DES')
        BoringSSL.SSL_CTX_set_grease_enabled(ctx_p, 1)
        BoringSSL.SSL_set1_groups_list(ssl_p,b'X25519:P-384:P-256') #X25519Kyber768Draft00

        BoringSSL.SSL_add_application_settings(ssl_p, b'h2', 2, b'', 0)
        bio_p = BoringSSL.BIO_new_connect(f'{host}:{port}'.encode('ascii'))
        BoringSSL.SSL_set_bio(ssl_p, bio_p, bio_p)

        return BoringSSLNetworkStream(ssl_p, ctx_p)
