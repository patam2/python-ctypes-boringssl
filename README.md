# python-ctypes-boringssl
a demo inspired by https://github.com/jonatron/boringssl-python-cffi/tree/master.. this one is closer to chrome's clienthello, but not there yet. 

To get my tls clienthello as similar to chromes, i had to bring out boringssl and attempt to use it with python. The backbone utilizing httpcore's functions is pretty much taken from the repo above, which is the only learning material for this type of project. 

The code itself is incredibly hacky and low quality. It uses boringssl as a DLL; ssl.dll & crypto.dll. In the BoringSSL source code, in order to match Chrome's fingerprint, I patched ssl/extensions.cc variable `kVerifySignatureAlgorithms` not to contain `SSL_SIGN_RSA_PKCS1_SHA1` (line 399)


Crypto.dll contains BIO functions, that's why it is used. Since I somehow could not figure out how to call the functions with their own names, I call them by their ordial:

```python
self.SSL_do_handshake = self.boringssl[301]
self.SSL_do_handshake.argtypes = [SSL]
self.SSL_do_handshake.restype = c_int
```

What's implemented from boringssl:
* GREASE
* ALPS
* ECDH
* min proto settings
