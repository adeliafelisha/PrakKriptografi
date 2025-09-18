# vigenere.py
# Otomatis sesuai soal:
#   PLAINTEXT = "ASPRAKGANTENG"
#   KEY       = "ADEL"
# Output: tabel enkripsi & dekripsi Vigenère (A=0..Z=25)

from typing import List

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A2I = {c: i for i, c in enumerate(ALPHABET)}
I2A = {i: c for i, c in enumerate(ALPHABET)}

def wrap_key(key: str, n: int) -> str:
    key = ''.join(ch for ch in key.upper() if ch.isalpha())
    if not key:
        raise ValueError("Key kosong.")
    return ''.join(key[i % len(key)] for i in range(n))

def vigenere_encrypt(plain: str, key: str) -> str:
    key_rep = wrap_key(key, len(plain))
    out = []
    for p, k in zip(plain.upper(), key_rep):
        out.append(I2A[(A2I[p] + A2I[k]) % 26])
    return ''.join(out)

def vigenere_decrypt(cipher: str, key: str) -> str:
    key_rep = wrap_key(key, len(cipher))
    out = []
    for c, k in zip(cipher.upper(), key_rep):
        out.append(I2A[(A2I[c] - A2I[k]) % 26])
    return ''.join(out)

def print_table(headers: List[str], rows: List[List[str]]):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    def fmt_row(row): return " | ".join(str(col).rjust(widths[i]) for i, col in enumerate(row))
    line = "-+-".join("-" * w for w in widths)
    print(fmt_row(headers)); print(line)
    for r in rows: print(fmt_row(r))
    print()

if __name__ == "__main__":
    PT  = "ASPRAKGANTENG"
    KEY = "ADEL"
    KEYREP = wrap_key(KEY, len(PT))
    CT  = vigenere_encrypt(PT, KEY)
    PT_BACK = vigenere_decrypt(CT, KEY)

    print("=== VIGENÈRE — ENKRIPSI ===")
    rows = []
    for i, (p, k, c) in enumerate(zip(PT, KEYREP, CT), start=1):
        rows.append([i, p, A2I[p], k, A2I[k], (A2I[p] + A2I[k]) % 26, c])
    print_table(["i", "PT", "n(PT)", "K", "n(K)", "(PT+K) mod26", "CT"], rows)
    print(f"Ciphertext: {CT}\n")

    print("=== VIGENÈRE — DEKRIPSI ===")
    rows = []
    for i, (c, k, p) in enumerate(zip(CT, KEYREP, PT_BACK), start=1):
        rows.append([i, c, A2I[c], k, A2I[k], (A2I[c] - A2I[k]) % 26, p])
    print_table(["i", "CT", "n(CT)", "K", "n(K)", "(CT−K) mod26", "PT"], rows)
    print(f"Plaintext hasil dekripsi: {PT_BACK}")
