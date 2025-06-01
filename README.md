# primepwn

Implementation of steaks4uce and SHAtter exploits from ipwndfu in C, as well as an option to send unpacked iBSS for pwned A5(X) and A6(X) devices.

## Features

- steaks4uce exploit for iPod touch 2nd generation
- SHAtter exploit for A4 devices
- Send unpacked iBSS for pwned A5(X) and A6(X) devices (`ipwndfu -l`)

## Building

`gcc primepwn.c -o primepwn -lirecovery-1.0`

## Usage

`./primepwn <unpacked ibss>`

- `<unpacked ibss>` is only for sending unpacked iBSS on pwned A5(X) and A6(X) devices
