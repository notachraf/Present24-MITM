# PRESENT24
- C implementation of PRESENT24 Encryption 
algoritme.
- Meet In The Middle attack on Double Present24.

## Overview
Present24 is an example of SPN (Substitution–permutation network)\
The number of rounds is fixed to 11, block size is 24 bits and the key size is also 24 bits. The non-linear layer is based on a single 4-bit S-box which was designed with hardware optimizations in mind. PRESENT is intended to be used in situations where low-power consumption and high chip efficiency is desired. 

## Compilation 
This implementation has only been tested on Windows and Unix platform.
1. Test Present24 Encryption and Decryption
    ```bash
    make present24
    ```
2. Perform Meet In The Middle attack 
    ```bash
    make mitm
    ```
    Used (plaintext, cipher) pairs :
    ```text
    (m1,c1) = (7e6359, 411b34) 
    (m2,c2) = (f55c52, 1c6195)
    ```

## Usage 
```bash
./bin/mitm [m1 c1 m2 c2] [number_of_threads]
```
