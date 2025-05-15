import os
import subprocess

if __name__=='__main__':
    party, port = 2, 12345
    print("I'm Bob!")
    x = 0x59667a44af6f56b7a0774523c6d07664df548705a38016968be03c22a6ef6844
    y = 0x0965ebee806a48a7870bd3107bcd93be78196f2241203ac4c78cfc98ce3605c4

    str_x = hex(x)[2:]
    str_x = "0" * (64 - len(str_x)) + str_x

    str_y = hex(y)[2:]
    str_y = "0" * (64 - len(str_y)) + str_y

    host = "127.0.0.1"

    cmd = f"./test_p256-ectf {str(party)} {str(port)} {str_x} {str_y} {host}"
    print(f"cmd: {cmd}")
    
    output = subprocess.check_output(cmd, shell=True)
    output_str = output.decode("utf-8")
    print(f"!output: {output_str}")
    outputs = output_str.split('\n')
    print(outputs)
    share = int(outputs[-2], 16)
    print(hex(share))

