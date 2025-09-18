# elgamal.py
# Otomatis sesuai soal:
#   p=37, g=3, x=2, k=15, PLAINTEXT="EZKRIPTOGRAFI"
# Skema ElGamal di Z_p*, huruf A..Z -> 0..25, satu k per pesan (c1 sama untuk semua huruf).

from typing import List, Tuple

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A2I = {c: i for i, c in enumerate(ALPHABET)}
I2A = {i: c for i, c in enumerate(ALPHABET)}

def print_table(headers, rows):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    def fmt_row(row): return " | ".join(str(col).rjust(widths[i]) for i, col in enumerate(row))
    line = "-+-".join("-" * w for w in widths)
    print(fmt_row(headers)); print(line)
    for r in rows: print(fmt_row(r))
    print()

def public_y(g: int, x: int, p: int) -> int:
    return pow(g, x, p)

def encrypt_text(pt: str, p: int, g: int, x: int, k: int) -> List[Tuple[int, int]]:
    y = public_y(g, x, p)
    c1 = pow(g, k, p)
    shared = pow(y, k, p)   # dipakai untuk semua huruf
    pairs = []
    for ch in pt.upper():
        m = A2I[ch]
        c2 = (m * shared) % p
        pairs.append((c1, c2))
    return pairs

def decrypt_pairs(pairs: List[Tuple[int, int]], p: int, x: int) -> str:
    out = []
    for c1, c2 in pairs:
        s = pow(c1, x, p)       # kunci bersama
        inv = pow(s, -1, p)     # invers modular
        m = (c2 * inv) % p
        out.append(I2A[m])
    return ''.join(out)

if __name__ == "__main__":
    p, g, x, k = 37, 3, 2, 15
    PT = "EZKRIPTOGRAFI"

    y = public_y(g, x, p)
    c1 = pow(g, k, p)
    shared = pow(y, k, p)
    pairs = encrypt_text(PT, p, g, x, k)

    print("=== ELGAMAL — PARAMETER & RUMUS ===")
    print(f"p={p}, g={g}, x={x}, k={k}")
    print(f"y = g^x mod p = {g}^{x} mod {p} = {y}")
    print(f"c1 = g^k mod p = {g}^{k} mod {p} = {c1}")
    print(f"shared = y^k mod p = {y}^{k} mod {p} = {shared}\n")

    print("=== ELGAMAL — ENKRIPSI (per huruf) ===")
    rows = []
    for i, (ch, (c1i, c2i)) in enumerate(zip(PT, pairs), start=1):
        rows.append([i, ch, A2I[ch], c1i, shared, f"({c1i}, {c2i})"])
    print_table(["i", "PT", "M", "c1", "shared (y^k mod p)", "CT (c1,c2)"], rows)

    print("Ciphertext (barisan pasangan):")
    print(" ".join(f"{a}:{b}" for a, b in pairs))
    print()

    print("=== ELGAMAL — DEKRIPSI (per huruf) ===")
    rows = []
    PT_BACK = []
    for i, (c1i, c2i) in enumerate(pairs, start=1):
        s = pow(c1i, x, p)
        inv = pow(s, -1, p)
        m = (c2i * inv) % p
        PT_BACK.append(I2A[m])
        rows.append([i, f"({c1i}, {c2i})", s, inv, m, I2A[m]])
    print_table(["i", "CT", "s=c1^x mod p", "s^{-1}", "m", "PT"], rows)

    print(f"Plaintext hasil dekripsi: {''.join(PT_BACK)}")
