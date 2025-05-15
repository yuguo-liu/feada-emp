import os
import subprocess

if __name__=='__main__':
    party, port = 1, 12345
    print("I'm Alice!")
    x = 0xaa80468d22f31ee672768b587526fbd88fb7fb3d304adec816d27fa7b34dd60d
    y = 0xbf276ab3b55cd976216973797d0a11f1328038dfd5834a357ada46abe359a794

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