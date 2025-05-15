import os
import subprocess

if __name__=='__main__':
    party, port = 2, 12345
    print("I'm Bob!")
    s = 0xd04e53b410ecc2290ed94f6d1ea1a8cd5480cce19cb8d5e3444f574e47524401
    c = 0x40a0ef21998d7adf64589c7eaf9a37eb5300c17528b4be7c9e598d52c31f741a
    m = 0xf895a8105c43adf8c24169fa27f872732acb1d76833df04cca0cb0175987897a6a4dbf731449daec1f93512aead107d5

    str_s = hex(s)[2:]
    str_s = "0" * (64 - len(str_s)) + str_s

    str_c = hex(c)[2:]
    str_c = "0" * (64 - len(str_c)) + str_c

    str_m = hex(m)[2:]
    str_m = "0" * (96 - len(str_m)) + str_m

    host = "127.0.0.1"

    cmd = f"./test_tls-prf-320-2-shares {str(party)} {str(port)} {str_s} {str_c} {str_m} {host}"
    print(f"cmd: {cmd}")
    
    output = subprocess.check_output(cmd, shell=True)
    output_str = output.decode("utf-8")
    print(f"!output: {output_str}")
    outputs = output_str.split('\n')
    print(outputs)
    key = int(outputs[-3], 16)
    hash = int(outputs[-2], 16)
    print(hex(key))
    print(hex(hash))