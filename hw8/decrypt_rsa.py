e = 5163359
n = 7189579
phi_n=7182720


ciphertexts = [1311615, 3205173, 475476, 7177361, 533234, 475476, 7177361, 533234,
               6660386, 1438457, 6389756, 533234, 6212161, 3043363, 1956017, 6800648,
               6800648, 1492801, 533234, 1956017, 533234, 7177361, 3043363, 3092893,
               6212161, 3043363, 6389756, 2271115]


d = pow(e, -1, phi_n)


def decrypt(ciphertext, d, n):
    return pow(ciphertext, d, n)
    
decrypted_msg= [decrypt(c,d,n) for c in ciphertexts]


print("Decrypted Text:", decrypted_msg)


original_msg = ''.join([chr(decrypted) for decrypted in decrypted_msg])

print(original_msg)
