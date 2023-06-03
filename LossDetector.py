import threading
import time

import requests


class LossDetector(threading.Thread):
    def __init__(self, stopEvent, transactions, messageQueue):
        self.stopEvent = stopEvent
        self.transactions = transactions
        self.messageQueue = messageQueue
        super().__init__()

    def run(self):
        while not self.stopEvent.is_set():
            response = requests.get("https://gradecoin.xyz/transaction")
            currentTransactions = response.json()
            for transaction in self.transactions:
                if not (transaction in currentTransactions):
                    self.messageQueue.put("error")
            time.sleep(3)
