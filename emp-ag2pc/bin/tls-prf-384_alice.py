import os
import subprocess

if __name__=='__main__':
    party, port = 1, 12345
    print("I'm Alice!")
    s = 0xd37ea8b78aafcf19ebf4194fcb43f9a521db20c42445325b444f574e47524401
    c = 0xe105c540dd7273d6ed89775ed58e0d67d99edac40241dad3eccda240e3291649
    m = 0xc3e9eb6a1808d9b376fe76598e38423a13a1415665fc2771aaf88b7431bc0817

    str_s = hex(s)[2:]
    str_s = "0" * (64 - len(str_s)) + str_s

    str_c = hex(c)[2:]
    str_c = "0" * (64 - len(str_c)) + str_c

    str_m = hex(m)[2:]
    str_m = "0" * (64 - len(str_m)) + str_m

    host = "127.0.0.1"

    cmd = f"./test_tls-prf-384 {str(party)} {str(port)} {str_s} {str_c} {str_m} {host}"
    print(f"cmd: {cmd}")
    
    output = subprocess.check_output(cmd, shell=True)
    output_str = output.decode("utf-8")
    print(f"!output: {output_str}")
    outputs = output_str.split('\n')
    print(outputs)
    share = int(outputs[-2], 16)
    print(hex(share))