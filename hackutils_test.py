from hackutils import *

class TestEnc:
    encode = Encode()
    
    def Testb32(self):
        data = "Når+!*"
        encdata = ""

        assert encdata == self.encode.b32(data)

class TestDec:
    decode = Decode()
        
    
    def Testb32(self):
        data = "Når+!*"
        encdata = ""

        assert data == self.decode.b32(encdata)

class TestEncDec:
    decode = ""
    encode = ""

    def __init__(self) -> None:
        self.decode = Decode()
        self.encode = Encode()

    def Testb32(self):
        data = "Hello!"
        encdata = ""
        
        assert encdata == self.encode.b32(data)
        assert data == self.decode.b32(encdata)

class TestAnalyze:
    analyze = Analyze()

    def TestParquet(self):
        pass

class TestPayload:
    payload = Payload()

    def TestGenerate(self):
        x = 0
        all = self.payload.generate("http://example.com")
        # 14 has first remote payload
        for pl in all:
            x += 1
            if x >= 14:
                assert "http://example.com" in pl
            assert "|placeholder|" not in pl