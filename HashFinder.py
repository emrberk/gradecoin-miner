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
        newPayload = {}
        while not hash.startswith("0" * self.hashZeros):
            tries += 1
            newPayload = {
                "transaction_list": self.payload["transaction_list"],
                "nonce": self.order + tries,
                "timestamp": self.payload["timestamp"]
            }
            serializedData = json.dumps(newPayload, separators=(',', ':'))
            hash_object = hashlib.blake2s(serializedData.encode())
            hash_hex = hash_object.hexdigest()
            hash = hash_hex
            tries += 1
        self.payload = {
            "transaction_list": newPayload["transaction_list"],
            "nonce": newPayload["nonce"],
            "timestamp": newPayload["timestamp"],
            "hash": hash
        }
        self.queue.put(self.payload)
