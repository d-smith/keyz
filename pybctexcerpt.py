# All code in thus module copied from https://github.com/vbuterin/pybitcointools/tree/patch-1 

# Below code ASSUMES binary inputs and compressed pubkeys


import hmac
import hashlib
import binascii
import re
import base64
import time
import random
import hmac

MAINNET_PRIVATE = b'\x04\x88\xAD\xE4'
MAINNET_PUBLIC = b'\x04\x88\xB2\x1E'
TESTNET_PRIVATE = b'\x04\x35\x83\x94'
TESTNET_PUBLIC = b'\x04\x35\x87\xCF'
PRIVATE = [MAINNET_PRIVATE, TESTNET_PRIVATE]
PUBLIC = [MAINNET_PUBLIC, TESTNET_PUBLIC]
DEFAULT = (MAINNET_PRIVATE, MAINNET_PUBLIC)


# BIP32 child key derivation


def raw_bip32_ckd(rawtuple, i, prefixes=DEFAULT):
    vbytes, depth, fingerprint, oldi, chaincode, key = rawtuple
    i = int(i)

    private = vbytes == prefixes[0]

    if private:
        priv = key
        pub = privtopub(key)
    else:
        priv = None
        pub = key

    if i >= 2**31:
        if not priv:
            raise Exception("Can't do private derivation on public key!")
        I = hmac.new(chaincode, b'\x00'+priv[:32]+encode(i, 256, 4), hashlib.sha512).digest()
    else:
        I = hmac.new(chaincode, pub+encode(i, 256, 4), hashlib.sha512).digest()
    if private:
        newkey = add_privkeys(I[:32]+B'\x01', priv)
        fingerprint = bin_hash160(privtopub(key))[:4]
    else:
        newkey = add_pubkeys(compress(privtopub(I[:32])), key)
        fingerprint = bin_hash160(key)[:4]

    return (vbytes, depth + 1, fingerprint, i, I[32:], newkey)


def bip32_serialize(rawtuple, prefixes=DEFAULT):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    i = encode(i, 256, 4)
    chaincode = encode(hash_to_int(chaincode), 256, 32)
    keydata = b'\x00'+key[:-1] if vbytes == prefixes[0] else key
    bindata = vbytes + from_int_to_byte(depth % 256) + fingerprint + i + chaincode + keydata
    return changebase(bindata+bin_dbl_sha256(bindata)[:4], 256, 58)


def bip32_deserialize(data, prefixes=DEFAULT):
    dbin = changebase(data, 58, 256)
    if bin_dbl_sha256(dbin[:-4])[:4] != dbin[-4:]:
        raise Exception("Invalid checksum")
    vbytes = dbin[0:4]
    depth = from_byte_to_int(dbin[4])
    fingerprint = dbin[5:9]
    i = decode(dbin[9:13], 256)
    chaincode = dbin[13:45]
    key = dbin[46:78]+b'\x01' if vbytes == prefixes[0] else dbin[45:78]
    return (vbytes, depth, fingerprint, i, chaincode, key)


def is_xprv(text, prefixes=DEFAULT):
    vbytes, depth, fingerprint, i, chaincode, key = bip32_deserialize(text, prefixes)
    return vbytes == prefixes[0]


def is_xpub(text, prefixes=DEFAULT):
    vbytes, depth, fingerprint, i, chaincode, key = bip32_deserialize(text, prefixes)
    return vbytes == prefixes[1]


def raw_bip32_privtopub(rawtuple, prefixes=DEFAULT):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    newvbytes = prefixes[1]
    return (newvbytes, depth, fingerprint, i, chaincode, privtopub(key))


def bip32_privtopub(data, prefixes=DEFAULT):
    return bip32_serialize(raw_bip32_privtopub(bip32_deserialize(data, prefixes), prefixes), prefixes)


def bip32_ckd(key, path, prefixes=DEFAULT, public=False):
    if isinstance(path, (list, tuple)):
        pathlist = map(str, path)
    else:
        path = str(path)
        pathlist = parse_bip32_path(path)
    for i, p in enumerate(pathlist):
        key = bip32_serialize(raw_bip32_ckd(bip32_deserialize(key, prefixes), p, prefixes), prefixes)
    return key if not public else bip32_privtopub(key)

def bip32_master_key(seed, prefixes=DEFAULT):
    I = hmac.new(
            from_string_to_bytes("Bitcoin seed"), 
            from_string_to_bytes(seed), 
            hashlib.sha512
        ).digest()
    return bip32_serialize((prefixes[0], 0, b'\x00'*4, 0, I[32:], I[:32]+b'\x01'), prefixes)


def bip32_bin_extract_key(data, prefixes=DEFAULT):
    return bip32_deserialize(data, prefixes)[-1]


def bip32_extract_key(data, prefixes=DEFAULT):
    return safe_hexlify(bip32_deserialize(data, prefixes)[-1])


def bip32_derive_key(key, path, prefixes=DEFAULT, **kwargs):
    return bip32_extract_key(bip32_ckd(key, path, prefixes, **kwargs), prefixes)

# Exploits the same vulnerability as above in Electrum wallets
# Takes a BIP32 pubkey and one of the child privkeys of its corresponding
# privkey and returns the BIP32 privkey associated with that pubkey


def raw_crack_bip32_privkey(parent_pub, priv, prefixes=DEFAULT):
    vbytes, depth, fingerprint, i, chaincode, key = priv
    pvbytes, pdepth, pfingerprint, pi, pchaincode, pkey = parent_pub
    i = int(i)

    if i >= 2**31:
        raise Exception("Can't crack private derivation!")

    I = hmac.new(pchaincode, pkey+encode(i, 256, 4), hashlib.sha512).digest()

    pprivkey = subtract_privkeys(key, I[:32]+b'\x01')

    newvbytes = prefixes[0]
    return (newvbytes, pdepth, pfingerprint, pi, pchaincode, pprivkey)


def crack_bip32_privkey(parent_pub, priv, prefixes=DEFAULT):
    dsppub = bip32_deserialize(parent_pub, prefixes)
    dspriv = bip32_deserialize(priv, prefixes)
    return bip32_serialize(raw_crack_bip32_privkey(dsppub, dspriv, prefixes), prefixes)

def from_string_to_bytes(a):
        return a if isinstance(a, bytes) else bytes(a, 'utf-8')

def encode(val, base, minlen=0):
        base, minlen = int(base), int(minlen)
        code_string = get_code_string(base)
        result_bytes = bytes()
        while val > 0:
            curcode = code_string[val % base]
            result_bytes = bytes([ord(curcode)]) + result_bytes
            val //= base

        pad_size = minlen - len(result_bytes)

        padding_element = b'\x00' if base == 256 else b'1' \
            if base == 58 else b'0'
        if (pad_size > 0):
            result_bytes = padding_element*pad_size + result_bytes

        result_string = ''.join([chr(y) for y in result_bytes])
        result = result_bytes if base == 256 else result_string

        return result

def decode(string, base):
        if base == 256 and isinstance(string, str):
            string = bytes(bytearray.fromhex(string))
        base = int(base)
        code_string = get_code_string(base)
        result = 0
        if base == 256:
            def extract(d, cs):
                return d
        else:
            def extract(d, cs):
                return cs.find(d if isinstance(d, str) else chr(d))

        if base == 16:
            string = string.lower()
        while len(string) > 0:
            result *= base
            result += extract(string[0], code_string)
            string = string[1:]
        return result
    
code_strings = {
    2: '01',
    10: '0123456789',
    16: '0123456789abcdef',
    32: 'abcdefghijklmnopqrstuvwxyz234567',
    58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    256: ''.join([chr(x) for x in range(256)])
}
    
def get_code_string(base):
    if base in code_strings:
        return code_strings[base]
    else:
        raise ValueError("Invalid base!")

def hash_to_int(x):
    if len(x) in [40, 64]:
        return decode(x, 16)
    return decode(x, 256)



def from_int_to_byte(a):
    return bytes([a])

def changebase(string, frm, to, minlen=0):
    if frm == to:
        return lpad(string, get_code_string(frm)[0], minlen)
    return encode(decode(string, frm), to, minlen)

def bin_dbl_sha256(s):
    bytes_to_hash = from_string_to_bytes(s)
    return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

def from_byte_to_int(a):
    return a



def privkey_to_pubkey(privkey):
    f = get_privkey_format(privkey)
    privkey = decode_privkey(privkey, f)
    if privkey >= N:
        raise Exception("Invalid privkey")
    if f in ['bin', 'bin_compressed', 'hex', 'hex_compressed', 'decimal']:
        return encode_pubkey(fast_multiply(G, privkey), f)
    else:
        return encode_pubkey(fast_multiply(G, privkey), f.replace('wif', 'hex'))

privtopub = privkey_to_pubkey

def get_privkey_format(priv):
    if isinstance(priv, int_types): return 'decimal'
    elif len(priv) == 32: return 'bin'
    elif len(priv) == 33: return 'bin_compressed'
    elif len(priv) == 64: return 'hex'
    elif len(priv) == 66: return 'hex_compressed'
    else:
        bin_p = b58check_to_bin(priv)
        if len(bin_p) == 32: return 'wif'
        elif len(bin_p) == 33: return 'wif_compressed'
        else: raise Exception("WIF does not represent privkey")
            
string_types = (str)
string_or_bytes_types = (str, bytes)
int_types = (int, float)

def decode_privkey(priv,formt=None):
    if not formt: formt = get_privkey_format(priv)
    if formt == 'decimal': return priv
    elif formt == 'bin': return decode(priv, 256)
    elif formt == 'bin_compressed': return decode(priv[:32], 256)
    elif formt == 'hex': return decode(priv, 16)
    elif formt == 'hex_compressed': return decode(priv[:64], 16)
    elif formt == 'wif': return decode(b58check_to_bin(priv),256)
    elif formt == 'wif_compressed':
        return decode(b58check_to_bin(priv)[:32],256)
    else: raise Exception("WIF does not represent privkey")

# Elliptic curve parameters (secp256k1)

P = 2**256 - 2**32 - 977
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx, Gy)

def encode_pubkey(pub, formt):
    if not isinstance(pub, (tuple, list)):
        pub = decode_pubkey(pub)
    if formt == 'decimal': return pub
    elif formt == 'bin': return b'\x04' + encode(pub[0], 256, 32) + encode(pub[1], 256, 32)
    elif formt == 'bin_compressed':
        return from_int_to_byte(2+(pub[1] % 2)) + encode(pub[0], 256, 32)
    elif formt == 'hex': return '04' + encode(pub[0], 16, 64) + encode(pub[1], 16, 64)
    elif formt == 'hex_compressed':
        return '0'+str(2+(pub[1] % 2)) + encode(pub[0], 16, 64)
    elif formt == 'bin_electrum': return encode(pub[0], 256, 32) + encode(pub[1], 256, 32)
    elif formt == 'hex_electrum': return encode(pub[0], 16, 64) + encode(pub[1], 16, 64)
    else: raise Exception("Invalid format!")
        
def to_jacobian(p):
    o = (p[0], p[1], 1)
    return o

def jacobian_double(p):
    if not p[1]:
        return (0, 0, 0)
    ysq = (p[1] ** 2) % P
    S = (4 * p[0] * ysq) % P
    M = (3 * p[0] ** 2 + A * p[2] ** 4) % P
    nx = (M**2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq ** 2) % P
    nz = (2 * p[1] * p[2]) % P
    return (nx, ny, nz)


def jacobian_add(p, q):
    if not p[1]:
        return q
    if not q[1]:
        return p
    U1 = (p[0] * q[2] ** 2) % P
    U2 = (q[0] * p[2] ** 2) % P
    S1 = (p[1] * q[2] ** 3) % P
    S2 = (q[1] * p[2] ** 3) % P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 1)
        return jacobian_double(p)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    nx = (R ** 2 - H3 - 2 * U1H2) % P
    ny = (R * (U1H2 - nx) - S1 * H3) % P
    nz = (H * p[2] * q[2]) % P
    return (nx, ny, nz)


def from_jacobian(p):
    z = inv(p[2], P)
    return ((p[0] * z**2) % P, (p[1] * z**3) % P)


def jacobian_multiply(a, n):
    if a[1] == 0 or n == 0:
        return (0, 0, 1)
    if n == 1:
        return a
    if n < 0 or n >= N:
        return jacobian_multiply(a, n % N)
    if (n % 2) == 0:
        return jacobian_double(jacobian_multiply(a, n//2))
    if (n % 2) == 1:
        return jacobian_add(jacobian_double(jacobian_multiply(a, n//2)), a)


def fast_multiply(a, n):
    return from_jacobian(jacobian_multiply(to_jacobian(a), n))


def fast_add(a, b):
    return from_jacobian(jacobian_add(to_jacobian(a), to_jacobian(b)))

def inv(a, n):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high//low
        nm, new = hm-lm*r, high-low*r
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def parse_bip32_path(path):
    """Takes bip32 path, "m/0'/2H" or "m/0H/1/2H/2/1000000000.pub", returns list of ints """
    path = path.lstrip("m/").rstrip(".pub")
    if not path:
        return []
    #elif path.endswith("/"):       incorrect for electrum segwit
    #    path += "0"
    patharr = []
    for v in path.split('/'):
        if not v: 
            continue
        elif v[-1] in ("'H"):  # hardened path
            v = int(v[:-1]) | 0x80000000
        else:                  # non-hardened path
            v = int(v) & 0x7fffffff
        patharr.append(v)
    return patharr


def add_privkeys(p1, p2):
    f1, f2 = get_privkey_format(p1), get_privkey_format(p2)
    return encode_privkey((decode_privkey(p1, f1) + decode_privkey(p2, f2)) % N, f1)


def encode_privkey(priv, formt, vbyte=128):
    if not isinstance(priv, int_types):
        return encode_privkey(decode_privkey(priv), formt, vbyte)
    if formt == 'decimal': return priv
    elif formt == 'bin': return encode(priv, 256, 32)
    elif formt == 'bin_compressed': return encode(priv, 256, 32)+b'\x01'
    elif formt == 'hex': return encode(priv, 16, 64)
    elif formt == 'hex_compressed': return encode(priv, 16, 64)+'01'
    elif formt == 'wif':
        return bin_to_b58check(encode(priv, 256, 32), int(vbyte))
    elif formt == 'wif_compressed':
        return bin_to_b58check(encode(priv, 256, 32) + b'\x01', int(vbyte))
    else: raise Exception("Invalid format!")
        
def bin_hash160(string):
    intermed = hashlib.sha256(string).digest()
    digest = ''
    try:
        digest = hashlib.new('ripemd160', intermed).digest()
    except:
        digest = RIPEMD160(intermed).digest()
    return digest

def hash160(string):
    return safe_hexlify(bin_hash160(string))

def hex_to_hash160(s_hex):
    return hash160(binascii.unhexlify(s_hex))

def bin_sha256(string):
    binary_data = string if isinstance(string, bytes) else bytes(string, 'utf-8')
    return hashlib.sha256(binary_data).digest()

def sha256(string):
    return bytes_to_hex_string(bin_sha256(string))

def subtract_privkeys(p1, p2):
    f1, f2 = get_privkey_format(p1), get_privkey_format(p2)
    k2 = decode_privkey(p2, f2)
    return encode_privkey((decode_privkey(p1, f1) - k2) % N, f1)

    
