import os, random, base64
from cryptography.fernet import Fernet

class X:
    def __init__(self):
        self.K = Fernet.generate_key()
        self.C = Fernet(self.K)
    def E(self, T):
        return self.C.encrypt(T.encode()).decode()
    def D(self, T):
        return self.C.decrypt(T.encode()).decode()
    def M(self):
        F = os.path.abspath(__file__)
        with open(F, "r", encoding="utf-8") as f: L = f.readlines()
        if not any("# OBF" in x for x in L):
            L = [x.replace(" ", random.choice(["", " ", "  "])) for x in L]
            random.shuffle(L)
            L.insert(0, "# OBF\n")
        L.insert(random.randint(0, len(L)), f"# M{random.randint(1000, 9999)}\n")
        C = base64.b64encode("".join(L).encode()).decode()
        with open(F, "w", encoding="utf-8") as f: f.write(f"import base64\nexec(base64.b64decode('{C}').decode())")

O = X()
T = "Secret"
print("E:", O.E(T))
print("D:", O.D(O.E(T)))
O.M()
