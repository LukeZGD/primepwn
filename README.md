# primepwn

C implementation of the steaks4uce, limera1n, and SHAtter bootrom exploits, ported from ipwndfu. Also supports sending images to pwned A5/A6/A12/A13 devices.

## Features

- steaks4uce - iPod touch 2nd gen
- limera1n - iPhone 3GS, iPod touch 3rd gen
- SHAtter - A4 devices (iPad 1, iPhone 4, iPod touch 4th gen)
- Image booting on pwned A5/A6/A12/A13 devices (equivalent to `ipwndfu -l` / `usbliter8ctl boot`)

## Building

`gcc primepwn.c -o primepwn -lirecovery-1.0` (or see `compile.sh`)

## Usage

#### Run exploit for the connected device

```
./primepwn
```

#### Send an image to a device in pwned DFU mode

```
./primepwn <image>
```
