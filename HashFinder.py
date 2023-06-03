import threading
import json
import hashlib


class HashFinder(threading.Thread):
    def __init__(self, payload, hashZeros, order, queue, stopEvent):
        self.payload = payload
        self.hashZeros = hashZeros
        self.order = order * 429496729
        self.queue = queue
        self.stopEvent = stopEvent
        super().__init__()

    def run(self):
        hash = ""
        tries = -1
        while not hash.startswith("0" * self.hashZeros) and not self.stopEvent.is_set():
            tries += 1
            self.payload["nonce"] = self.order + tries
            serializedData = json.dumps(self.payload, separators=(',', ':'))
            hash_object = hashlib.blake2s(serializedData.encode())
            hash_hex = hash_object.hexdigest()
            hash = hash_hex
            tries += 1
        if self.stopEvent.is_set():
            return
        self.payload["hash"] = hash
        self.queue.put(self.payload)
