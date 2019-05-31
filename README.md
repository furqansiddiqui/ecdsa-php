## :warning: Warning

This lib is provided WITHOUT warranty of any kind, use it at your own risk.

# ECDSA lib for PHP

This lib is designed to perform all ECC calculations and operations for my [**furqansiddiqui/bitcoin-php**](https://github.com/furqansiddiqui/bitcoin-php)
lib.

## Prerequisites

* PHP 7.2
* ext-gmp
* ext-bcmath

## Installation

`composer require furqansiddiqui/ecdsa-php`

### Change Log (>0.2.x)

From v0.2.x and onwards I have dropped all previous ECC curves (`Secp256k1` via `BcMath` and `Secp256k1` via `OpenSSL`) in favour of `GMP`. 
`BcMath` provided to be extremely slow as compared to `GMP` while performing ECC calculations. In fact, most of the code for ECC ops via `GMP` is
taken from [BitcoinECDSA.php](https://github.com/BitcoinPHP/BitcoinECDSA.php) lib, so all appreciations, kudos 
and thanks goes to developers and contributors over there!
