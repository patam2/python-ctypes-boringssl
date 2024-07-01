from ctypes import WinDLL, POINTER, c_char_p, c_void_p, c_int, c_uint, c_size_t, c_uint16, c_ushort


SSL_ALPN_selected = c_char_p
SSL_METHOD = c_void_p
SSL_CTX = POINTER(c_uint)
SSL = POINTER(c_uint)
BIO = POINTER(c_uint)
_STACK = POINTER(c_uint)
CRYPTO_BUFFER = POINTER(c_void_p)


class BoringSSL:
    def __init__(self, boringssl_dll, crypto_dll) -> None:
        self.boringssl = WinDLL(boringssl_dll)
        self.cryptodll = WinDLL(crypto_dll)


        #SSL_get0_alpn_selected
        self._SSL_get0_alpn_selected = self.boringssl[314]
        self._SSL_get0_alpn_selected.argtypes = [c_void_p, POINTER(SSL_ALPN_selected), POINTER(c_uint)]
        self._SSL_get0_alpn_selected.restype = None

        #SSL_do_handshake
        self.SSL_do_handshake = self.boringssl[301]
        self.SSL_do_handshake.argtypes = [SSL]
        self.SSL_do_handshake.restype = c_int

        #SSL_get_error 
        self.SSL_get_error = self.boringssl[350]
        self.SSL_get_error.argtypes = [SSL, c_int]
        self.SSL_get_error.restype = c_int
      
        #SSL_CTX_set_alpn_protos
        self.SSL_CTX_set_alpn_protos = self.boringssl[152]
        self.SSL_CTX_set_alpn_protos.argtypes = [SSL, c_char_p, c_size_t]
        self.SSL_CTX_set_alpn_protos.restype = c_int
      
        #BIO_new_connect
        self.BIO_new_connect = self.cryptodll[228]
        self.BIO_new_connect.argtypes = [c_char_p]
        self.BIO_new_connect.restype = BIO
        
        #BIO_set_conn_hostname 
        self.BIO_set_conn_hostname = self.cryptodll[255]
        self.BIO_set_conn_hostname.argtypes = [BIO, c_char_p]
        self.BIO_set_conn_hostname.restype = c_int

        #SSL_set_bio
        self.SSL_set_bio = self.boringssl[470]
        self.SSL_set_bio.argtypes = [SSL, BIO, BIO]
        self.SSL_set_bio.restype = None

        #SSL_CTX_NEW
        self.SSL_CTX_NEW = self.boringssl[113]
        self.SSL_CTX_NEW.argtypes = [SSL_METHOD]
        self.SSL_CTX_NEW.restype = SSL_CTX

        #SSL_NEW
        self.SSL_NEW = self.boringssl[427]
        self.SSL_NEW.argtypes = [SSL_CTX]
        self.SSL_NEW.restype = SSL

        #SSL_CONNECT
        self.SSL_CONNECT = self.boringssl[298]
        self.SSL_CONNECT.argtypes = [SSL]
        self.SSL_CONNECT.restype = c_int

        #SSL_READ
        self.SSL_READ = self.boringssl[437]
        self.SSL_READ.argtypes = [SSL, c_void_p, c_int]
        self.SSL_READ.restype = c_int

        #SSL_WRITE
        self.SSL_WRITE = self.boringssl[554]
        self.SSL_WRITE.argtypes = [SSL, c_void_p, c_int]
        self.SSL_WRITE.restype = c_int

        #TLS_METHOD
        self.TLS_method = self.boringssl[559]
        self.TLS_method.argtypes = []
        self.TLS_method.restype = SSL_METHOD

        #SSLv23_method
        self.SSLv23_method = self.boringssl[556]
        self.SSLv23_method.argtypes = []
        self.SSLv23_method.restype = SSL_METHOD
        
        #SSL_CTX_set_grease_enabled
        self.SSL_CTX_set_grease_enabled = self.boringssl[171]
        self.SSL_CTX_set_grease_enabled.argtypes = [SSL_CTX, c_int]
        self.SSL_CTX_set_grease_enabled.restype = None

        #SSL_CTX_get_ciphers
        self.SSL_CTX_get_ciphers = self.boringssl[88]
        self.SSL_CTX_get_ciphers.argtypes = [SSL_CTX]
        self.SSL_CTX_get_ciphers.restype = _STACK

        #SSL_CTX_set_strict_cipher_list
        self.SSL_CTX_set_strict_cipher_list = self.boringssl[204]
        self.SSL_CTX_set_strict_cipher_list.argtypes = [SSL_CTX, c_char_p]

        #SSL_set_tlsext_host_name
        self.SSL_set_tlsext_host_name = self.boringssl[521]
        self.SSL_set_tlsext_host_name.argtypes = [SSL, c_char_p]
        self.SSL_set_tlsext_host_name.restype = c_int

        #SSL_set1_groups_list  
        self.SSL_set1_groups_list   = self.boringssl[459]
        self.SSL_set1_groups_list.argtypes = [SSL_CTX, c_char_p]
        self.SSL_set1_groups_list.restype = c_int

        #SSL_add_application_settings
        self.SSL_add_application_settings = self.boringssl[281]
        self.SSL_add_application_settings.argtypes = [SSL, c_char_p, c_size_t, c_char_p, c_size_t]
        self.SSL_add_application_settings.restype = c_int

        #SSL_CTX_set_min_proto_version
        self.SSL_CTX_set_min_proto_version = self.boringssl[177]
        self.SSL_CTX_set_min_proto_version.argtypes = [SSL_CTX, c_uint16]
        self.SSL_CTX_set_min_proto_version.restype = c_int

        #SSL_CTX_set_signing_algorithm_prefs
        self._SSL_CTX_set_signing_algorithm_prefs = self.boringssl[202] 
        self._SSL_CTX_set_signing_algorithm_prefs.argtypes = [SSL_CTX, POINTER(c_uint16), c_size_t]
        self._SSL_CTX_set_signing_algorithm_prefs.restype = c_int


        #SSL_CTX_set1_sigalgs_list
        self.SSL_CTX_set1_sigalgs_list = self.boringssl[148]
        self.SSL_CTX_set1_sigalgs_list.argtypes = [SSL_CTX, c_char_p]
        self.SSL_CTX_set1_sigalgs_list.restype = c_int

        #SSL_set1_sigalgs_list
        self.SSL_set1_sigalgs_list = self.boringssl[463]
        self.SSL_set1_sigalgs_list.argtypes = [SSL, c_char_p]
        self.SSL_set1_sigalgs_list.restype = c_int

        #SSL_set_signing_algorithm_prefs
        self._SSL_set_signing_algorithm_prefs = self.boringssl[516]
        self._SSL_set_signing_algorithm_prefs.argtypes = [SSL, POINTER(c_uint16), c_size_t]
        self._SSL_set_signing_algorithm_prefs.restype = c_int


        #SSL_enable_ocsp_stapling
        self.SSL_enable_ocsp_stapling = self.boringssl[307]
        self.SSL_enable_ocsp_stapling.argtypes = [SSL]
        self.SSL_enable_ocsp_stapling.restype = None

        #SSL_enable_signed_cert_timestamps
        self.SSL_enable_signed_cert_timestamps = self.boringssl[308]
        self.SSL_enable_signed_cert_timestamps.argtypes = [SSL]
        self.SSL_enable_signed_cert_timestamps.restype = None

    def SSL_get0_alpn_selected(self, SSL_PTR):
            out_data = SSL_ALPN_selected(b'\0'*10)
            out_len = c_uint()
            self._SSL_get0_alpn_selected(SSL_PTR, (out_data), (out_len))
            print('selected ALPN:', out_data.value[:out_len.value].decode())
            return out_data.value[:out_len.value]
    
    def SSL_set_signing_algorithm_prefs(self, ctx_p, prefs, pref_len): #not working? not used...
        print((c_ushort * pref_len)(*prefs))
        return self._SSL_set_signing_algorithm_prefs(
              ctx_p,
              (c_ushort * pref_len)(*prefs),
              pref_len
         )

