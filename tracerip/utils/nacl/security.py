import hashlib

def get_sha2(attr):
    return hashlib.sha224(attr.encode('utf-8')).hexdigest()