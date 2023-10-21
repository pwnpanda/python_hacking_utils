from hackutils import *

class TestEnc:
    encode = Encode()
    data = "Når+!*"


    def testEncb32(self):
        encdata = "J3B2K4RLEEVA===="

        assert encdata == self.encode.b32(self.data.encode("utf-8"))
    
    def testEncb64(self):
        encdata = "TsOlcishKg=="

        assert encdata == self.encode.b64(self.data.encode("utf-8"))

    def testEncb64Url(self):
        # TODO find example with changes from normal b64
        encdata = "TsOlcishKg=="

        assert encdata == self.encode.b64url(self.data.encode("utf-8"))

    def testEncurl(self):
        data = "Hello there<>"
        encdata = "Hello+there%3C%3E"

        assert encdata == self.encode.url(data)

    def testEnchtml(self):
        data = "hello&there<>"
        encdata = "hello&amp;there&lt;&gt;"

        assert encdata == self.encode.html(data)

    def testEnchex(self):
        encdata = "0x4ec3a5722b212a"

        assert encdata == self.encode.hex(self.data)

    def testEnchexint(self):
        data = 134
        encdata = "0x86"

        assert encdata == self.encode.hexint(data)

    def testEnchexweb(self):
        encdata = "\\x4e\\xc3\\xa5\\x72\\x2b\\x21\\x2a"

        assert encdata == self.encode.hexweb(self.data)

class TestDec:
    decode = Decode()
    data = "Når+!*"
    
    def testDecb32(self):
        encdata = "J3B2K4RLEEVA===="

        assert self.data == self.decode.b32(encdata)
    
    def testDecb64(self):
        encdata = "TsOlcishKg=="

        assert self.data == self.decode.b64(encdata)

    def testDecb64url(self):
        encdata = "TsOlcishKg=="

        assert self.data == self.decode.b64url(encdata)

    def testDecurl(self):
        data = "Hello there<>"
        encdata = "Hello+there%3C%3E"

        assert data == self.decode.url(encdata)

    def testDechtml(self):
        data = "hello&there<>"
        encdata = "hello&amp;there&lt;&gt;"

        assert data == self.decode.html(encdata)

    def testDechex(self):
        encdata = "0x4ec3a5722b212a"

        assert self.data == self.decode.hex(encdata)

    def testDechexint(self):
        data = 134
        encdata = "0x86"

        assert data == self.decode.hexint(encdata)
    
    def testDechexweb(self):
        encdata = "\\x4e\\xc3\\xa5\\x72\\x2b\\x21\\x2a"

        assert self.data == self.decode.hexweb(encdata)

class TestEncDec:
    decode = Decode()
    encode = Encode()

    data = "Når+!*"


    def testEncDecb32(self):
        encdata = "J3B2K4RLEEVA===="
        
        assert encdata == self.encode.b32(self.data.encode("utf-8"))
        assert self.data == self.decode.b32(encdata)
        assert self.data == self.decode.b32(self.encode.b32(self.data.encode("utf-8")))

    def testEncDecb64(self):
        encdata = "TsOlcishKg=="
        
        assert encdata == self.encode.b64(self.data.encode("utf-8"))
        assert self.data == self.decode.b64(encdata)
        assert self.data == self.decode.b64(self.encode.b64(self.data.encode("utf-8")))

    def testEncDecb64url(self):
        encdata = "TsOlcishKg=="
        
        assert encdata == self.encode.b64url(self.data.encode("utf-8"))
        assert self.data == self.decode.b64url(encdata)
        assert self.data == self.decode.b64url(self.encode.b64url(self.data.encode("utf-8")))

    def testEncDecurl(self):
        data = "Hello there<>"
        encdata = "Hello+there%3C%3E"
        
        assert encdata == self.encode.url(data)
        assert data == self.decode.url(encdata)
        assert data == self.decode.url(self.encode.url(data))

    def testEncDechtml(self):
        data = "hello&there<>"
        encdata = "hello&amp;there&lt;&gt;"
        
        assert encdata == self.encode.html(data)
        assert data == self.decode.html(encdata)
        assert data == self.decode.html(self.encode.html(data))

    def testEncDechex(self):
        encdata = "0x4ec3a5722b212a"
        
        assert encdata == self.encode.hex(self.data)
        assert self.data == self.decode.hex(encdata)
        assert self.data == self.decode.hex(self.encode.hex(self.data))

    def testEncDechexint(self):
        data = 134
        encdata = "0x86"
        
        assert encdata == self.encode.hexint(data)
        assert data == self.decode.hexint(encdata)
        assert data == self.decode.hexint(self.encode.hexint(data))

    def testEncDechexweb(self):
        encdata = "\\x4e\\xc3\\xa5\\x72\\x2b\\x21\\x2a"
        
        assert encdata == self.encode.hexweb(self.data)
        assert self.data == self.decode.hexweb(encdata)
        assert self.data == self.decode.hexweb(self.encode.hexweb(self.data))

class TestAnalyze:
    analyze = Analyze()

    def testParquet(self):
        pass

class TestPayload:
    payload = Payload()

    def testGenerate(self):
        all = self.payload.generate("http://example.com")
        # 14 has first remote payload
        for pl in all.split("\n"):
            assert "|placeholder|" not in pl

if __name__ == "__main__":
    TestEnc().testEncb32()
    TestDec().testDecb32()
    TestEncDec().testEncDecb32()
    TestAnalyze().testParquet()
    TestPayload().testGenerate()