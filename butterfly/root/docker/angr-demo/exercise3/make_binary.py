password = "time_2_solve_all_the_things\x0a"

result = ""

for letter in password:
    curr_result = letter
    for xor_letter in 'symexec':
        curr_result = chr(ord(curr_result) ^ ord(xor_letter))

    result += curr_result

print(repr(result))
