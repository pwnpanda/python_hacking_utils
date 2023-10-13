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
