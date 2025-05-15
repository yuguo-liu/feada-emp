import os
import subprocess

if __name__=='__main__':
    party, port = 1, 12345
    print("I'm Alice!")
    seed = 0xc4b4ebe8578f4ca02a8d833d2cde604ba8896ab61ae7fdd274a8df438c903f56
    m = 0xbce43e9894393a897121bab60d3581b4bf36738dde8fa202554bbb16931d7897cec17bb36c3519dd827f7fb4f0962af0

    str_seed = hex(seed)[2:]
    str_seed = "0" * (64 - len(str_seed)) + str_seed

    str_m = hex(m)[2:]
    str_m = "0" * (96 - len(str_m)) + str_m

    host = "127.0.0.1"

    cmd = f"./test_tls-prf-96 {str(party)} {str(port)} {str_seed} {str_m} {host}"
    print(f"cmd: {cmd}")
    
    output = subprocess.check_output(cmd, shell=True)
    output_str = output.decode("utf-8")
    print(f"!output: {output_str}")
    outputs = output_str.split('\n')
    print(outputs)
    verifyData = int(outputs[-2], 16)
    print(hex(verifyData))
