## bech32

Fork of https://github.com/fiatjaf/bech32 hopefully making it easier to use.

### Install

```
pip install git+https://github.com/Quorra-Auth/bech32
```

### Usage

```
import bech32
url = b"https://service.example/lnurl-pay"
encoded = bech32.encode_bytes("lnurl", url)
decoded = bech32.decode_bytes("lnurl", encoded)
assert decoded == url
```

### Disclaimer

Vibecoding, vibecoding...
