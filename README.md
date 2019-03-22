# ECDSA (Elliptic Curves) lib for PHP

This lib is to generate vectors/curves for cryptocurrency libs

### Fail-safe Computing

Backup means of computing curves (where possible) are available as a fail-safe measure, i.e. A `Secp256k1` curve vector 
computed using BcMath may also be computed using OpenSSL lib for comparison.

It means that when generating a public key from private key using `Secp256k1` curve, you may perform this action twice 
using separate methods in this lib and then compare results as they MUST be "precise".

## Prerequisite

* PHP ^7.2
* ext-bcmath
* ext-openssl

## Installation

`composer require furqansiddiqui/ecdsa-php`

## Supported Curves

ID | Curve | Lib
---| --- | ---
Secp256k1 | secp256k1 | BcMath
Secp256k1_OpenSSL | secp256k1 | OpenSSL