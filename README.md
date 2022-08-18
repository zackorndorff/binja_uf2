# [UF2](https://github.com/microsoft/uf2) Firmware loader for Binary Ninja

(kinda rough but working; it is worth precisely what you paid for it)

## Features

* Recognizes and loads the [UF2 (USB Flashing
  Format)](https://github.com/microsoft/uf2) firmware file format.
    * We create a Binary Ninja segment for each 512-byte block in the UF2 file
      at the moment, that seems like the best way to handle it.
* If your board happens to be a RP2040, it sets the current arch to ARM

## What doesn't work

* The UF2 firmware format doesn't contain an entry point, or architecture
  metadata (beyond the name of the device), so we can't provide that info to
  Binary Ninja.
    * PRs welcome to map device -> arch, as long as it doesn't break if you
      don't have that arch installed. Realistically you may just want to
      copy-paste then implement your own BinaryView with device-specific memory
      map info, etc.
* The UF2 format doesn't have sections, or segment permissions, so we just claim
  everything is code. I think this is the correct lie to tell binja.
  You will want to manually create sections to guide the linear sweep. 
* We tell binja the address size is always 32-bits, since we have to pick
  a number.

## Installation

`git clone` this repository into your Binary Ninja plugins directory.

See the [official Binary Ninja
documentation](https://docs.binary.ninja/guide/plugins.html) for more details.

## Why?

I recently came across an embedded Raspberry Pi Pico board that had some
firmware on it that I wanted to analyze. (I missed DEF CON this year, but some
friends found me a spare badge somehow.) I dumped the firmware and found that I
couldn't load it, so I hacked up [Kevin Colley's IDA
loader](https://github.com/kjcolley7/UF2-IDA-Loader) to load it into binja.

This code is like 100 lines, I'm mostly posting it so I don't have to write it
again if I see this format again.

## License

This project copyright Zack Orndorff (@zackorndorff) and is available under the
MIT license. It uses code from Kevin Colley's IDA loader which is also under the
MIT license. See the top of [uf2.py](uf2.py) for details.

