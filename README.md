# python_hacking_utils
A python module of commonly used utilities that can be included or used by itself to speed up common processes, like url encoding and decoding!
Use by doing: `import py_hack_utils` (py_hack_utils.py should be in the current folder you are executing from - e.g. the current directory when running python/python3)

# Install
`pip install -r requirements.txt` (potentially `python -m pip install -r requirements.txt`)

# Overview of functions:
All functions are split into logical subclasses.
These work by calling: `subclass.function(data)`
## Subclasses
* Encode / Decode
    * base32
    * base64
    * base64_url format
    * url encoding
    * html encoding
* Analyze
    * parquet (hadoop db delta)


# ToDo
- [] Payload listing
- [] Payload generation
- [] Encode/Decode only special characters
- [] to Hex
- [] to unicode
- [] Chars to homoglyphs
- [] list characters with homoglyphs
- [] Analyze file formats
- [] Autodocument which functions exist and the structure