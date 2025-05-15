import os
import subprocess

if __name__=='__main__':
    party, port = 2, 12345
    print("I'm Bob!")
    seed = 0xc4b4ebe8578f4ca02a8d833d2cde604ba8896ab61ae7fdd274a8df438c903f56
    m = 0x29260e341e76c7c05fe77ab4a607fc54359fb953f7db9299e5b3746a5351b232685cfae47cc361351b4d19a547537b16

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