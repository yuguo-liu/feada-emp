import os
import subprocess
import secrets
import time
import json

def generate_hex_string(length):
    byte_length = (length + 1) // 2
    hex_str = secrets.token_hex(byte_length)
    return hex_str[:length]

if __name__=='__main__':
    party, port = 1, 12345
    print("I'm Alice!")

    aes_measure_data = {}
    
    for block_length in [16, 32, 64, 128]:
        aes_measure_data[f'#block = {block_length}'] = 0

    for i in range(10):
        port = 12345
        for block_length in [16, 32, 64, 128]:
            print(f"==> block length {block_length} in epoch {i} <==")
            bob_m         = "0" * (32 * block_length)
            bob_key_share = "0"
            bob_iv_share  = "0"

            alice_m         = generate_hex_string(32 * block_length)
            alice_auth_data = "01020304050607080900"
            alice_key_share = "0102030405060708090a0b0c0d0e0f00"
            alice_iv_share  = "0102030405060708090a0b0c"
            r_com           = "8dd1485d13f3728ec81f2fab68c304b3"
            commitment      = "592e332c40056a34e250f4a0ba579980db85c24ede7ba66b09b67ccee100a65d"
            
            len_c_i = len(bob_m) * 4
            len_a_i = len(alice_auth_data) * 4

            host = "127.0.0.1"

            cmd = f"./test_predicate-aes-gcm-2pc {str(party)} {str(port)} {bob_m} {bob_key_share} {bob_iv_share} {alice_m} {alice_auth_data} {alice_key_share} {alice_iv_share} {r_com} {commitment} {str(len_c_i)} {str(len_a_i)} {host}"
            print(f"cmd: {cmd}")
            
            st = time.time()
            output = subprocess.check_output(cmd, shell=True)
            duration = time.time() - st

            port += 1

            aes_measure_data[f'#block = {block_length}'] += duration * 100
    
    with open("pre-aes-gcm-2pc.json", "w") as f:
        json.dump(aes_measure_data, f, indent=4)