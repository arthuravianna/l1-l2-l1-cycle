from eth_abi import decode_abi, encode_abi

class Wallet:
    def __init__(self):
        self.erc20 = {}     # Fungible Token Balance     -> token_addr: amount
        self.erc721 = []    # Non-Fungible Token Balance -> token_addr: [token_id_0,...,token_id_n]

    #def deposit(self, token_addr, amount):
    def deposit(self, deposit_data):
        if "token_id" not in deposit_data:
            if deposit_data["token_addr"] not in self.erc20:
                self.erc20[deposit_data["token_addr"]] = 0

            self.erc20[deposit_data["token_addr"]] += deposit_data["amount"]
        else:
            if deposit_data["token_addr"] not in self.erc721:
                self.erc721[deposit_data["token_addr"]] = []

            self.erc721[deposit_data["token_addr"]].append(deposit_data["token_id"])


    def withdraw(self, token_addr, amount):
        if token_addr not in self.tokens:
            raise Exception("The wallet doesn't have the required token.")

        if self.tokens[token_addr] < amount:
            raise Exception(f"The wallet doesn't have enough funds. Required: {amount}, Available: {self.tokens[token_addr]}")

        self.tokens[token_addr] -= amount

    def __str__(self):
        d = {'ERC20': self.erc20, 'ERC721': self.erc721}
        return str(d)