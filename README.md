# primepwn

C implementation of the steaks4uce, limera1n, and SHAtter bootrom exploits (ported from ipwndfu), with support for sending unpacked iBSS to pwned A5(X) and A6(X) devices.

## Features

- steaks4uce exploit (iPod touch 2nd gen)
- limera1n exploit (iPhone 3GS, iPod touch 3rd gen)
- SHAtter exploit (A4 devices: iPad 1, iPhone 4, iPod touch 4th gen)
- Send unpacked iBSS to pwned A5(X) and A6(X) devices (equivalent to `ipwndfu -l`)

## Building

`gcc primepwn.c -o primepwn -lirecovery-1.0`

## Usage

#### Run exploit (auto-selects based on device)

`./primepwn`

#### Send unpacked iBSS (A5/A6 devices in pwned DFU)

`./primepwn [unpacked ibss]`
