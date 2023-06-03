from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import base64
import json
import requests
import time
import jwt
from datetime import datetime
import hashlib
import random


class Miner:
    def __init__(self):
        self.baseUrl = "https://gradecoin.xyz"
        self.fingerprint = "49fc44505a0cafe4f210f7cd157c5997b3b464e7482b6a6f0870f5f36270ace7"
        self.tries = 0

    def register(self):
        temp_key = b'0000000000000000'
        iv = b'emreemreemreemre'
        cipher = Cipher(algorithms.AES(temp_key), modes.CBC(iv), backend=default_backend())
        padder = padding.PKCS7(128).padder()
        # Apply padding to the data
        P_AR = {
            "student_id": "e238059",
            "passwd": "2hcpXmGIwMQgnShsXqT62J6QPGpy2rch",
            "public_key": """-----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2BvZIYo8aRPMvvotEy5o
        j/OHFyv+S5GiLFrs9m4qwfeT7s0/32zLc1uDvBMLKSvafUbGad9ghrlkdtc0d9yM
        NU/B2fsSf9etJIAIjvbm6P/FLGiHWRKrHKyhKMNqlzRuBJXZ6Sx/k+gdKXhc0W30
        hsYODdMQh1iIGHDs000joCjnA3e9qfqROwiD36u2DAeCllrrO2U2FizgzQA/hxpf
        H1YE3fUj1wOUi1nKM1k+osHgogEV94249vr4Nt1365HXQGgCq/tsGHz70Kuh2v5Z
        lU1XMaGBeZgjkRKCKhmlXYte91171CsBiONng1MtzBvdCyi8A+PrLjqNu/jjP94Y
        5QIDAQAB
        -----END PUBLIC KEY-----"""
        }
        serialized_P_AR = json.dumps(P_AR)
        padded_data = padder.update(serialized_P_AR.encode()) + padder.finalize()
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize() # C_AR

        with open("gradecoin.pub", "rb") as file2:
            public_key = serialization.load_pem_public_key(
                file2.read(),
                backend=default_backend()
            )

        encrypted_temp_key = public_key.encrypt(
            temp_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
        data = {
            "c": base64.b64encode(encrypted_data).decode(),
            "iv": base64.b64encode(iv).decode(),
            "key": base64.b64encode(encrypted_temp_key).decode()
        }
        serialized_data = json.dumps(data)
        headers = {
            'Content-Type': 'application/json'
        }
        response = requests.post(f"{self.baseUrl}/register", data=serialized_data, headers=headers)
        response_json = response.json()
        self.fingerprint = response_json.get('message')

    @staticmethod
    def sign_jwt(payload):
        with open('./private_key.pem', 'rb') as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None,
                backend=default_backend()
            )
        return jwt.encode(payload, private_key, algorithm='RS256', headers={'alg': 'RS256', 'typ': 'JWT'})

    def makeTransaction(self, source, target, amount):
        data = {
            "source": source,
            "target": target,
            "amount": amount,
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        }
        serializedData = json.dumps(data, separators=(',', ':'))
        md5_hash = hashlib.md5(serializedData.encode()).hexdigest()

        payloadJwt = {
            "tha": md5_hash,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        signedJwt = self.sign_jwt(payloadJwt)
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {signedJwt}'
        }
        response = requests.post(f"{self.baseUrl}/transaction", data=serializedData, headers=headers)
        if response.ok:
            with open("./transactions.log", 'a+') as f:
                f.write(json.dumps(response.json()))
                f.write("\n")
        else:
            print(f"Transaction unsuccessful Source: {source} Target: {target} Amount: {amount}")

    def getConfig(self):
        response = requests.get(f"{self.baseUrl}/config")
        response = response.json()
        self.networkName = response.get('name')
        self.baseUrl += response.get('url_prefix')
        self.blockSize = response.get('block_transaction_count')
        self.hashZeros = response.get('hash_zeros')
        self.blockReward = response.get('block_reward')
        self.gasFee = response.get('tx_gas_fee')
        self.upperLimit = response.get('tx_upper_limit')
        self.lowerLimit = response.get('tx_lower_limit')
        self.trafficReward = response.get('tx_traffic_reward')
        self.bots = list(response.get('bots').keys())

    def getTransactions(self):
        response = requests.get(f"{self.baseUrl}/transaction")
        return response.json()

    def mineBlock(self):
        transactions = self.getTransactions()
        myTransactions = {}
        for key, val in transactions.items():
            if val["source"] == self.fingerprint:
                myTransactions[key] = val
        for key in myTransactions:
            del transactions[key]

        others = len(transactions)
        othersNeeded = self.blockSize - 1
        maxCount = others // othersNeeded
        if len(myTransactions) == 0 and maxCount > 0 and self.tries <= 2:
            self.makeTransaction(self.fingerprint, self.bots[random.randint(0, len(bots) - 1)], self.lowerLimit)
            time.sleep(2)
            self.tries += 1
            self.mineBlock()
        if maxCount == 0:
            print("Not enough transactions")
            return

        numBlocks = min(len(myTransactions), maxCount)
        transactionIds = list(transactions.keys())
        myTransactionIds = list(myTransactions.keys())

        for i in range(numBlocks):
            mined = False
            nonce = 1
            print("i will try to find a nonce..")
            while not mined:
                payload = {
                    "transaction_list": [myTransactionIds[0]] + [transactionId for transactionId in transactionIds[:othersNeeded]],
                    "nonce": nonce,
                    "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
                }
                hash = self.blake2s(payload)
                if hash.startswith("0" * 5):
                    print("hash =", hash, self.hashZeros)
                if hash.startswith("0" * self.hashZeros):
                    payload["hash"] = hash
                    json_string = json.dumps(payload, separators=(',', ':'))
                    jwtData = {
                        "tha": hash,
                        "iat": int(time.time()),
                        "exp": int(time.time()) + 3600,
                    }
                    print('jwtdata =', jwtData)
                    signedJwt = self.sign_jwt(jwtData)
                    print('signedjwt =', signedJwt)
                    print('jsonstring =', json_string)
                    headers = {
                        'Content-Type': 'application/json',
                        'Authorization': f'Bearer {signedJwt}'
                    }
                    try:
                        response = requests.post(f"{self.baseUrl}/block", data=json_string, headers=headers)
                        print("i mined something")
                        with open("./blocks.log", 'a+') as f:
                            f.write(json.dumps(response.json()))
                            f.write("\n")
                        myTransactionIds = myTransactionIds[1:]
                        transactionIds = transactionIds[othersNeeded:]
                        mined = True

                    except Exception as e:
                        print(e)
                else:
                    nonce += 1
                    continue


    def blake2s(self, data):
        serializedData = json.dumps(data, separators=(',', ':'))
        hash_object = hashlib.blake2s(serializedData.encode())
        hash_hex = hash_object.hexdigest()
        return hash_hex




if __name__ == "__main__":
    miner = Miner()
    miner.getConfig()
    bots = miner.bots
    #for bot in bots:
    #    miner.makeTransaction(miner.fingerprint, bot, miner.lowerLimit)
    miner.mineBlock()




