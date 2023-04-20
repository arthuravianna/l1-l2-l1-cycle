from eth_abi import decode_abi, encode_abi

class Wallet:
    def __init__(self):
        self.erc20 = {}     # Fungible Token Balance     -> token_addr: amount
        self.erc721 = {}    # Non-Fungible Token Balance -> token_addr: [token_id_0,...,token_id_n]

    def deposit(self, deposit_data):
        if "token_id" not in deposit_data:
            if deposit_data["token_addr"] not in self.erc20:
                self.erc20[deposit_data["token_addr"]] = 0

            self.erc20[deposit_data["token_addr"]] += deposit_data["amount"]
        else:
            if deposit_data["token_addr"] not in self.erc721:
                self.erc721[deposit_data["token_addr"]] = set()

            self.erc721[deposit_data["token_addr"]].add(deposit_data["token_id"])


    def withdraw(self, withdraw_data):
        if "token_id" not in withdraw_data:
            if withdraw_data["token_addr"] not in self.erc20:
                raise Exception(f"The wallet doesn't posses the token {withdraw_data["token_addr"]}.")

            if self.erc20[withdraw_data["token_addr"]] < withdraw_data["amount"]:
                raise Exception(f"The wallet doesn't have enough funds.")

            self.erc20[withdraw_data["token_addr"]] -= withdraw_data["amount"]
        else:
            if withdraw_data["token_addr"] not in self.erc721:
                raise Exception(f"The wallet doesn't posses the token {withdraw_data["token_addr"]}.")

            if withdraw_data["token_id"] not in self.erc721[withdraw_data["token_addr"]]:
                raise Exception(f"The wallet doesn't have the NFT {withdraw_data["token_addr"]} with ID {withdraw_data["token_id"]}.")

            self.erc271[withdraw_data["token_addr"]].remove(withdraw_data["token_id"])

    def __str__(self):
        d = {'ERC20': self.erc20, 'ERC721': self.erc721}
        return str(d)