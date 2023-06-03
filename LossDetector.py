import multiprocessing
import time

import requests


class LossDetector(multiprocessing.Process):
    def __init__(self, transactions, messageQueue):
        self.transactions = transactions
        self.messageQueue = messageQueue
        super().__init__()

    def run(self):
        while True:
            response = requests.get("https://gradecoin.xyz/transaction")
            currentTransactions = response.json()
            for transaction in self.transactions:
                if not (transaction in currentTransactions):
                    self.messageQueue.put("error")
            time.sleep(3)
