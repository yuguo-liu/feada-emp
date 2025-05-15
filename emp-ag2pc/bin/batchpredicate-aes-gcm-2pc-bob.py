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
    party, port = 2, 12345
    print("I'm Bob!")
    
    for i in range(10):
        port = 12345
        for block_length in [16, 32, 64, 128]:
            bob_m           = generate_hex_string(block_length * 32)
            bob_key_share   = "102030405060708090a0b0c0d0e0f000"
            bob_iv_share    = "102030405060708090a0b0c0"

            alice_m         = "0" * (32 * block_length)
            alice_auth_data = "0" * 20
            alice_key_share = "0"
            alice_iv_share  = "0"
            r_com           = "0"
            commitment      = "0"
            
            len_c_i = len(bob_m) * 4
            len_a_i = len(alice_auth_data) * 4

            host = "127.0.0.1"

            cmd = f"./test_predicate-aes-gcm-2pc {str(party)} {str(port)} {bob_m} {bob_key_share} {bob_iv_share} {alice_m} {alice_auth_data} {alice_key_share} {alice_iv_share} {r_com} {commitment} {str(len_c_i)} {str(len_a_i)} {host}"
            print(f"cmd: {cmd}")
            
            output = subprocess.check_output(cmd, shell=True)
            output_str = output.decode("utf-8")
            print(f"!output: {output_str}")
            outputs = output_str.split('\n')
            print(outputs)
            cipher, tag = outputs[-3], outputs[-2]

            print(f"get cipher 0x{cipher}")
            print(f"get tag    0x{tag}")

            port += 1