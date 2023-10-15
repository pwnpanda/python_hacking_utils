# python_hacking_utils
A python module of commonly used utilities that can be included or used by itself to speed up common processes, like url encoding and decoding!


# Install
`pip install -r requirements.txt` (potentially `python -m pip install -r requirements.txt`)

# Usage
You can use this as a library or as a command line tool.
1. Usage as a library:
    1. Do: `import hackutils` (hackutils.py should be in the current folder you are executing from - e.g. the current directory when running python/python3)
    2. Call function:
        a. `hackutils.Payload().list()`
        b. `hackutils.Decode()..url("%3c")`
2. Usage as command line tool:
    1. `python hackutils.py p -l` 
    2. `python hackutils.py d -url "%3c`

# Overview of functions:
All functions are split into logical subclasses.
These work by calling: `subclass.function(data)`
Example: `encode.url("/")`

## Subclasses
* Encode / Decode
    * b32 (base32)
    * b64 (base64)
    * b64url (base64 url format)
    * url (url encoding)
    * html (html encoding)

* Analyze
    * parquet (hadoop data storage format)

* Payload
    * list  (List all payloads)
    * generate (Generate payloads with a target set - e.g. a URL or an IP)

# ToDo
- [X] Payload listing
- [x] Payload generation
- [ ] Encode/Decode only special characters
- [ ] to Hex
- [ ] to unicode
- [ ] Chars to homoglyphs
- [ ] list characters with homoglyphs
- [ ] Analyze file formats
- [ ] Look for:
    * Common file formats needing analysis
    * Common encoding / decoding
    * Common payloads & test-strings (E.G. ACAR)