import multiprocessing
import json
import hashlib


class HashFinder(multiprocessing.Process):
    def __init__(self, payload, hashZeros, order, queue):
        self.payload = payload
        self.hashZeros = hashZeros
        self.order = order * 429496729
        self.queue = queue
        super().__init__()

    def run(self):
        hash = ""
        tries = -1
        while not hash.startswith("0" * self.hashZeros):
            tries += 1
            self.payload["nonce"] = self.order + tries
            serializedData = json.dumps(self.payload, separators=(',', ':'))
            hash_object = hashlib.blake2s(serializedData.encode())
            hash_hex = hash_object.hexdigest()
            hash = hash_hex
            tries += 1
        self.payload["hash"] = hash
        self.queue.put(self.payload)
