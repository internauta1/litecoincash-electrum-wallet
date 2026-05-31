import secrets
import hashlib

WORDLIST = [
    "apple", "banana", "cat", "dog", "earth", "forest",
    "gold", "house", "ice", "jungle", "king", "lemon",
    "moon", "night", "orange", "planet", "queen", "river",
    "stone", "tree", "unity", "victory", "water", "xenon",
    "yellow", "zebra"
]


class Mnemonic:

    def generate(self, words=12):

        result = []

        for _ in range(words):
            result.append(secrets.choice(WORDLIST))

        return " ".join(result)

    def to_seed(self, mnemonic):

        return hashlib.sha256(
            mnemonic.encode()
        ).hexdigest()
