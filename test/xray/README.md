# Xray-core interoperability

Checks the server against the VMess client encoding of Xray-core, which
v2rayN and most Xray based clients use, with request options set the way
Xray's outbound sets them. Covers every security type, global padding,
authenticated length, TCP and UDP, response shaping, and the fallback taken
by a request rejected for missing encryption.

```sh
cd test/xray && go test -race .
```

`none` with authenticated length is skipped: Xray ignores the option for
`none`, sing-vmess encrypts the length, so the two never interoperated.
