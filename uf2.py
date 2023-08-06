"""
Quick and dirty Binja loader for UF2
"""
"""
Copyright 2022 Zack Orndorff

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


UF2 parsing code borrowed from https://github.com/kjcolley7/UF2-IDA-Loader ,
which is MIT licensed (thanks!)

Copyright (c) 2021 Kevin Colley

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
import struct
import os

from binaryninja import BinaryView, Architecture, BinaryReader
from binaryninja.enums import SectionSemantics, SegmentFlag, SymbolType

class UF2(BinaryView):
    name = "UF2"
    long_name = "UF2 Firmware"

    def __init__(self, data, *args, **kwargs):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data):
        try:
            magic = data.read(0,4)
            if magic != b"UF2\n":
                return False
            header = UF2Header(BinaryReader(data))
            processor = header.get_processor()
            if processor is not None:
                print("UF2 file detected: processor is %s" % (processor,))
                return True
        except Exception as e:
            print("UF2 exception: %s" % e)
    
        return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0

    def perform_get_address_size(self):
        return 4

    def init(self):
        br = BinaryReader(self.raw)
        header = UF2Header(br)
        # So the UF2 format has this weird thing where for hardware bootloader
        # reasons they wrap each chunk of data in a header. So your actual
        # firmware is interleaved every few hundred bytes with yet another
        # header.
        for i in range(header.m_numBlocks):
            br.seek(i * UF2_BLOCK_SIZE)
            chunk = UF2Header(br)
            self.add_auto_segment(chunk.m_targetAddr, chunk.m_payloadSize,
                    UF2_BLOCK_DATA_OFFSET + i * UF2_BLOCK_SIZE,
                    chunk.m_payloadSize,
                    (SegmentFlag.SegmentContainsCode |
                     SegmentFlag.SegmentContainsData |
                     SegmentFlag.SegmentDenyWrite    |
                     SegmentFlag.SegmentReadable     |
                     SegmentFlag.SegmentExecutable))
            
        if any((
                    "RP2040" in header.get_processor(),
                    "Microchip (Atmel) SAMD21" in header.get_processor()
        )):
            self.arch = Architecture['armv7']
            self.platform = self.arch.standalone_platform
        else:
            print("Unknown processor type", header.get_processor())

        return True

def u32(s):
    return struct.unpack("<I", s)[0]

UF2_BLOCK_SIZE = 0x200
UF2_FIRST_MAGIC = 0x0A324655
UF2_SECOND_MAGIC = 0x9E5D5157
UF2_FINAL_MAGIC = 0x0AB16F30
UF2_DATA_BLOCK_SIZE = 0x1dc
UF2_BLOCK_DATA_OFFSET = 0x20

UF2_FAMILY_ID_MAP = {
    0x16573617: "Microchip (Atmel) ATmega32",
    0x1851780a: "Microchip (Atmel) SAML21",
    0x1b57745f: "Nordic NRF52",
    0x1c5f21b0: "ESP32",
    0x1e1f432d: "ST STM32L1xx",
    0x202e3a91: "ST STM32L0xx",
    0x21460ff0: "ST STM32WLxx",
    0x2abc77ec: "NXP LPC55xx",
    0x300f5633: "ST STM32G0xx",
    0x31d228c6: "GD32F350",
    0x04240bdf: "ST STM32L5xx",
    0x4c71240a: "ST STM32G4xx",
    0x4fb2d5bd: "NXP i.MX RT10XX",
    0x53b80f00: "ST STM32F7xx",
    0x55114460: "Microchip (Atmel) SAMD51",
    0x57755a57: "ST STM32F401",
    0x5a18069b: "Cypress FX2",
    0x5d1a0a2e: "ST STM32F2xx",
    0x5ee21072: "ST STM32F103",
    0x647824b6: "ST STM32F0xx",
    0x68ed2b88: "Microchip (Atmel) SAMD21",
    0x6b846188: "ST STM32F3xx",
    0x6d0922fa: "ST STM32F407",
    0x6db66082: "ST STM32H7xx",
    0x70d16653: "ST STM32WBxx",
    0x7eab61ed: "ESP8266",
    0x7f83e793: "NXP KL32L2x",
    0x8fb060fe: "ST STM32F407VG",
    0xada52840: "Nordic NRF52840",
    0xbfdd4eee: "ESP32-S2",
    0xc47e5767: "ESP32-S3",
    0xd42ba06c: "ESP32-C3",
    0xe48bff56: "Raspberry Pi RP2040",
    0x00ff6919: "ST STM32L4xx",
}

class UF2Header(object):

    def __init__(self, f):
        self.m_magicStart0 = u32(f.read(4))
        self.m_magicStart1 = u32(f.read(4))
        self.m_flags = u32(f.read(4))
        self.m_targetAddr = u32(f.read(4))
        self.m_payloadSize = u32(f.read(4))
        self.m_blockNo = u32(f.read(4))
        self.m_numBlocks = u32(f.read(4))
        self.m_fileSize = u32(f.read(4))
        self.m_data = f.read(UF2_DATA_BLOCK_SIZE)
        self.m_magicEnd = u32(f.read(4))
    
    def get_processor(self):
        matches = 0
        if self.m_magicStart0 == UF2_FIRST_MAGIC:
            matches += 1
        
        if self.m_magicStart1 == UF2_SECOND_MAGIC:
            matches += 1
        
        if self.m_magicEnd == UF2_FINAL_MAGIC:
            matches += 1
        
        if matches == 0:
            return None
        
        processor = "unknown"
        if self.m_flags & 0x2000:
            if self.m_fileSize in UF2_FAMILY_ID_MAP:
                processor = UF2_FAMILY_ID_MAP[self.m_fileSize]
        
        return processor

UF2.register()
