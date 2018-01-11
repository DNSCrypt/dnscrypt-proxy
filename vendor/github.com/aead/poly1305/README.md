[![Godoc Reference](https://godoc.org/github.com/aead/poly1305?status.svg)](https://godoc.org/github.com/aead/poly1305)

## The poly1305 message authentication code

Poly1305 is a fast, one-time authentication function created by Daniel J. Bernstein.  
It is infeasible for an attacker to generate an authenticator for a message without the key.  
However, a key must only be used for a single message. Authenticating two different messages  
with the same key allows an attacker to forge authenticators for other messages with the same key.

### Installation
Install in your GOPATH: `go get -u github.com/aead/poly1305`

### Requirements
All Go versions >= 1.7 are supported.

### Performance

#### AMD64
Hardware: Intel i7-6500U 2.50GHz x 2  
System: Linux Ubuntu 16.04 - kernel: 4.4.0-62-generic  
Go version: 1.8.0  

**AVX2**  
```
name                 speed              cpb
Sum_64-4             1.60GB/s ± 0%      1.39
Sum_256-4            2.32GB/s ± 1%      1.00 
Sum_1K-4             3.61GB/s ± 1%      0.65 
Sum_8K-4             4.20GB/s ± 1%      0.55
Write_64-4           2.04GB/s ± 0%      1.14
Write_256-4          3.50GB/s ± 2%      0.67
Write_1K-4           4.08GB/s ± 2%      0.57
Write_8K-4           4.25GB/s ± 2%      0.55
```

**x64**  

```
name                 speed              cpb
Sum_64-4             1.60GB/s ± 1%      1.46
Sum_256-4            2.11GB/s ± 3%      1.10
Sum_1K-4             2.35GB/s ±13%      0.99
Sum_8K-4             2.47GB/s ±13%      0.94
Write_64-4           1.81GB/s ± 5%      1.29
Write_256-4          2.24GB/s ± 4%      1.04   
Write_1K-4           2.55GB/s ± 0%      0.91
Write_8K-4           2.63GB/s ± 0%      0.88
```
