class SHA256Context:
    def __init__(self):
        self.hashes = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        self.data = bytearray(64)
        self.datalen = 0
        self.bitlen = 0
        self.K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

    def sha256_transform(self):
        w = [0] * 64
        for i in range(16):
            w[i] = self.data[i*4] << 24 | self.data[i*4+1] << 16 | self.data[i*4+2] << 8 | self.data[i*4+3]
        
        for i in range(16, 64):
            s0 = (w[i-15] >> 7 | w[i-15] << (32-7)) ^ (w[i-15] >> 18 | w[i-15] << (32-18)) ^ (w[i-15] >> 3)
            s1 = (w[i-2] >> 17 | w[i-2] << (32-17)) ^ (w[i-2] >> 19 | w[i-2] << (32-19)) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = self.hashes

        for i in range(64):
            S1 = (e >> 6 | e << (32-6)) ^ (e >> 11 | e << (32-11)) ^ (e >> 25 | e << (32-25))
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + self.K[i] + w[i]) & 0xFFFFFFFF
            S0 = (a >> 2 | a << (32-2)) ^ (a >> 13 | a << (32-13)) ^ (a >> 22 | a << (32-22))
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        self.hashes = [(x + y) & 0xFFFFFFFF for x, y in zip(self.hashes, [a, b, c, d, e, f, g, h])]
        # print hex(self.hashes)
        # print(f"{self.hashes[0]:08x} {self.hashes[1]:08x} {self.hashes[2]:08x} {self.hashes[3]:08x} {self.hashes[4]:08x} {self.hashes[5]:08x} {self.hashes[6]:08x} {self.hashes[7]:08x}")

    def update(self, data):
        # print("Update")
        # data padding to 64 bytes
        # this is some kind of tweak to avoid sha256 workarounds on Telechips
        if len(data) < 64:
            data += bytes(64 - len(data))
        
        # print data as hex
        # print(data.hex())
        
        data_len = len(data)
        self.bitlen += data_len * 8
        fill_data = bytearray(data)

        while len(fill_data) > 0:
            if self.datalen + len(fill_data) < 64:
                self.data[self.datalen:self.datalen+len(fill_data)] = fill_data
                self.datalen += len(fill_data)
                break
            load_len = 64 - self.datalen
            self.data[self.datalen:] = fill_data[:load_len]
            self.sha256_transform()
            self.datalen = 0
            fill_data = fill_data[load_len:]

    def digest(self):
        # Pad the remaining data
        # print(f"Digest: {self.datalen}")
        # pad_len = 64 - self.datalen
        # if pad_len < 9:
        #     pad_len += 64
        
        # this is some kind of tweak to avoid sha256 workarounds on Telechips
        pad_len = 64

        pad = bytearray([0x80] + [0x00]*(pad_len-9) + list(self.bitlen.to_bytes(8, byteorder='big')))
        # printout pad data in hex format
        # print(pad.hex())
        
        self.update(pad)

        out_digest = bytearray()
        for h in self.hashes:
            out_digest.extend(h.to_bytes(4, byteorder='big'))
        return out_digest
