# python_hacking_utils
A python module of commonly used utilities that can be included or used by itself to speed up common processes, like url encoding and decoding!
Use by doing: `import py_hack_utils` (py_hack_utils.py should be in the current folder you are executing from - e.g. the current directory when running python/python3)

# Install
`pip install -r requirements.txt` (potentially `python -m pip install -r requirements.txt`)

# Overview of functions:
All functions are split into logical subclasses.
These work by calling: `subclass.function(data)`
Example: `encode.b32`

## Subclasses
* Encode / Decode
    * b32 (base32)
    * b64 (base64)
    * b64url (base64 url format)
    * url (url encoding)
    * html (html encoding)
* Analyze
    * parquet (hadoop data storage format)


# ToDo
- [ ] Payload listing
- [ ] Payload generation
- [ ] Encode/Decode only special characters
- [ ] to Hex
- [ ] to unicode
- [ ] Chars to homoglyphs
- [ ] list characters with homoglyphs
- [ ] Analyze file formats
- [ ] Autodocument which functions exist and the structure
- [ ] Look for:
    * Common file formats needing analysis
    * Common encoding / decoding
    * Common payloads & test-strings (E.G. ACAR)