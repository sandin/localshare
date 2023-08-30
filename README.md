# LocalShare

A simple P2P file sharing network base on [Noise Protocol Framework](https://noiseprotocol.org/).


## Build

```
cargo build
```


## Usage

Generate your keyring file:
```
localshare keygen <your.keyring>
```

Responder:
```
localshare server 0.0.0.0:8080 --key <your.keyring>
```

Initiator:
```
localshare client 127.0.0.1:8080 --key <your.keyring>
```

