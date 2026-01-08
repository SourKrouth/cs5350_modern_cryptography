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
key_string= input("Enter the key string: ").lower()
if not key_string.isalpha():
    print("Bad offset")
    sys.exit(1)

# Calculate ciphertext
ciphertext = ""
for i in range(0, len(plaintext)):
    ciphertext += chr((ord(plaintext[i]) - ord('a') + ord(key_string[i % len(key_string)]) - ord('a')) % 26 + ord('a'))
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
# Assume key is of max length T
# Try key lengths up to T
# For each key length, find the best fit for each stream using frequency analysis
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

def get_streams(c, t):
    s_list = []
    for i in range(0, t):
        j = i
        s = ""
        while j < len(c):
            s += c[j]
            j += t
        s_list.append(s)
    return s_list

def calculate_k_for_stream(stream):
    best_diff = math.inf
    best_key = None
    for k in range(0, 26):
        p = get_plaintext(stream, k)
        count = letter_count(p)
        p_2 = calculate_p_value(count)
        diff = abs(p_base - p_2)
        if diff < best_diff:
            best_diff = diff
            best_key = k
    return best_key, best_diff

def get_key(ks):
    k_str = ""
    for k in ks:
        k_str += chr(k + ord('a'))
    return k_str

def get_key_length(c):
    MAX_KEY_LENGTH = 5
    best_diff = math.inf 
    key_length = MAX_KEY_LENGTH
    for t in range(1, MAX_KEY_LENGTH + 1):
        first_stream = get_streams(c, t)[0]
        _, diff = calculate_k_for_stream(first_stream)
        if diff < best_diff:
            best_diff = diff
            key_length = t
    return key_length

def calculate_plaintext(c, k):
    p = ""
    for i in range(0, len(c)):
       # ciphertext += chr((ord(plaintext[i]) - ord('a') + ord(key_string[i % len(key_string)]) - ord('a')) % 26 + ord('a'))
       p += chr((ord(c[i]) - ord('a') - ord(k[i % len(k)]) - ord('a')) % 26 + ord('a')) 
    return p

print("-----------")
t = get_key_length(ciphertext)
print(f"CALCULATED KEY LENGTH={t}")
# There are t streams now
# Perform frequency analysis on each stream to determine the best choice for a key
streams = get_streams(ciphertext, t)
keys = []
for stream in streams:
    k, _ = calculate_k_for_stream(stream)
    keys.append(k)

key = get_key(keys)

print()
print("CALCULATED KEY:")
print(f"\t{key}")
print(f"CALCULATED PLAINTEXT:")
print(f"\t{calculate_plaintext(ciphertext, key)}")