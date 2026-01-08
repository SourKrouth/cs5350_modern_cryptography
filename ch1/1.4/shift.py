import sys
import math

english_freq = {
    "a": 8.2,
    "b": 1.5,
    "c": 2.8,
    "d": 4.3,
    "e": 12.7,
    "f": 2.2,
    "g": 2.0,
    "h": 6.1,
    "i": 7.0,
    "j": 0.2,
    "k": 0.8,
    "l": 4.0,
    "m": 2.4,
    "n": 6.7,
    "o": 1.5,
    "p": 1.9,
    "q": 0.1,
    "r": 6.0,
    "s": 6.3,
    "t": 9.1,
    "u": 2.8,
    "v": 1.0,
    "w": 2.4,
    "x": 0.2,
    "y": 2.0,
    "z": 0.1
}

# Get plaintext and offset from user
plaintext = input("Enter some plaintext to encrypt (no spaces): ").lower()
if not plaintext.isalpha():
    print("Bad input")
    sys.exit(1)
offset = int(input("Enter the cipher shift [0-25]: "))
if offset < 0 or offset > 25:
    print("Bad offset")
    sys.exit(1)

# Calculate ciphertext
ciphertext = ""
for i in range(0, len(plaintext)):
    ciphertext += chr((ord(plaintext[i]) - ord('a') + offset) % 26 + ord('a'))
print()
print("PLAINTEXT:")
print(f"\t{plaintext}")
print("CIPHERTEXT:")
print(f"\t{ciphertext}")

# Perform attack
# Calculate baseline for english language
print()
p_base = 0
for l,v in english_freq.items():
    p_base += v/100*v/100
print(f"Baseline p^2 for English language: {p_base}")

# Compare all key possiblities to baseline (keyspace)
# For each key, calculate what the corresponding plaintext would be given the ciphertext
# For that ciphertext, calculate the p^2 value
# Keep track of the best p^2 value and corresponding key
def get_plaintext(c, k):
    p = ""
    for i in range(0, len(c)):
        p += chr((ord(c[i]) - ord('a') - k) % 26 + ord('a'))
    return p

def letter_count(p):
    count = {
        "a": 0,
        "b": 0,
        "c": 0,
        "d": 0,
        "e": 0,
        "f": 0,
        "g": 0,
        "h": 0,
        "i": 0,
        "j": 0,
        "k": 0,
        "l": 0,
        "m": 0,
        "n": 0,
        "o": 0,
        "p": 0,
        "q": 0,
        "r": 0,
        "s": 0,
        "t": 0,
        "u": 0,
        "v": 0,
        "w": 0,
        "x": 0,
        "y": 0,
        "z": 0
    }
    for i in range(0, len(p)):
        count[p[i]] += 1
    for k,v in count.items():
        count[k] = count[k] / len(p)
    return count

def calculate_p_value(count_dict):
    p_2 = 0
    for l, p in count_dict.items():
        p_2 += english_freq[l]/100 * p/100
    return p_2

print("-----------")
best_diff = math.inf
best_key = None
best_p = None
for k in range(0, 26):
    p = get_plaintext(ciphertext, k)
    count = letter_count(p)
    p_2 = calculate_p_value(count)
    diff = abs(p_base - p_2)
    if diff < best_diff:
        best_diff = diff
        best_key = k
        best_p = p_2
    print(f"p^2 for k={k}: {p_2}")

print()
print(f"Best p^2 is {best_p} for k={best_key} with difference {best_diff}")
print("CALCULATED PLAINTEXT:")
print(get_plaintext(ciphertext, best_key))