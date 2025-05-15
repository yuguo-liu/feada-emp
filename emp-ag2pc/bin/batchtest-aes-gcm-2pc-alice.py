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
            print(f"==> block length {block_length} in epoch {i}<==")
            bob_m         = generate_hex_string(block_length * 32)
            bob_key_share = "0"
            bob_iv_share  = "0"

            alice_auth_data = generate_hex_string(20)
            alice_key_share = generate_hex_string(32)
            alice_iv_share  = generate_hex_string(24)
            
            len_c_i = len(bob_m) * 4
            len_a_i = len(alice_auth_data) * 4

            host = "127.0.0.1"

            cmd = f"./test_aes-gcm-2pc {str(party)} {str(port)} {bob_m} {bob_key_share} {bob_iv_share} {alice_auth_data} {alice_key_share} {alice_iv_share} {str(len_c_i)} {str(len_a_i)} {host}"
            print(f"cmd: {cmd}")
            
            st = time.time()
            output = subprocess.check_output(cmd, shell=True)
            duration = time.time() - st
            port += 1

            aes_measure_data[f'#block = {block_length}'] += duration * 100

    with open("aes-gcm-2pc.json", "w") as f:
        json.dump(aes_measure_data, f, indent=4)
