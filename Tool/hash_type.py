import hashlib

class  Encrypt:
    def __init__(self, data):
        self.data = data

    def hash_sha1(self):
        sha1 = hashlib.sha1()
        sha1.update(self.data.encode('utf-8'))

        return sha1.hexdigest()
    
    def hash_sha224(self):
        sha224 = hashlib.sha224()
        sha224.update(self.data.encode('utf-8'))

        return sha224.hexdigest()

    def hash_sha384(self):
        sha384 = hashlib.sha384()
        sha384.update(self.data.encode('utf-8'))

        return sha384.hexdigest()

    def hash_blake2b(self):
        blake2b = hashlib.blake2b()
        blake2b.update(self.data.encode('utf-8'))

        return blake2b.hexdigest()
    
    def hash_blake2s(self):
        blake2s = hashlib.blake2s()
        blake2s.update(self.data.encode('utf-8'))

        return blake2s.hexdigest()

    def hash_md5(self):
        md5 = hashlib.md5()
        md5.update(self.data.encode('utf-8'))

        return md5.hexdigest()
    
