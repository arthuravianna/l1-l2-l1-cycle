# Copyright 2022 Cartesi Pte. Ltd.
#
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

from os import environ
import traceback
import logging
import requests
import json
from eth_abi import decode_abi, encode_abi

from wallet import Wallet

# Default header for ERC-20 transfers coming from the Portal, which corresponds
# to the Keccak256-encoded string "ERC20_Transfer", as defined at
# https://github.com/cartesi/rollups/blob/main/onchain/rollups/contracts/facets/ERC20PortalFacet.sol.
ERC20_TRANSFER_HEADER = b'Y\xda*\x98N\x16Z\xe4H|\x99\xe5\xd1\xdc\xa7\xe0L\x8a\x990\x1b\xe6\xbc\t)2\xcb]\x7f\x03Cx'

# Function selector to be called during the execution of a voucher that transfers funds,
# which corresponds to the first 4 bytes of the Keccak256-encoded result of "transfer(address,uint256)"
TRANSFER_FUNCTION_SELECTOR = b'\xa9\x05\x9c\xbb'

# Default header for ERC-721 transfers coming from the Portal, which corresponds
# to the Keccak256-encoded string "ERC721_Transfer", as defined at
# https://github.com/cartesi-corp/rollups/blob/main/onchain/rollups/contracts/facets/ERC721PortalFacet.sol
ERC721_TRANSFER_HEADER = b'd\xd9\xdeE\xe7\xdb\x1c\n|\xb7\x96\n\xd2Q\x07\xa67\x9bj\xb8[0DO:\x8drHW\xc1\xacx'

# Function selector to be called during the execution of a voucher that transfers ERC-721, which
# corresponds to the first 4 bytes of the Keccak256-encoded result of 'safeTransferFrom(address,address,uint256)'
SAFE_TRANSFER_FROM_SELECTOR = b'B\x84.\x0e'

accounts = {} # public address: Wallet

logging.basicConfig(level="INFO")
logger = logging.getLogger(__name__)

rollup_server = environ["ROLLUP_HTTP_SERVER_URL"]
logger.info(f"HTTP rollup_server url is {rollup_server}")

def hex2str(hex):
    """
    Decodes a hex string into a regular string
    """
    return bytes.fromhex(hex[2:]).decode("utf-8")

def str2hex(str):
    """
    Encodes a string as a hex string
    """
    return "0x" + str.encode("utf-8").hex()

def post(endpoint, msg):
    payload_hex = str2hex(msg)
    response = request.post(rollup_server + endpoint, json={"payload": payload_hex})
    logger.info(f"Received {endpoint} response status {response.status_code}.")

def process_deposit(payload):
    binary_payload = bytes.fromhex(payload[2:])

    # look up the header to discover if it is a ERC20 or ERC721 deposit
    header = decode_abi(['bytes32'], binary_payload)[0]

    deposit_data = None
    notice = {"type": "deposit", "token": None, "token_addr": None}
    if header == ERC20_TRANSFER_HEADER:
        deposit_data = decode_erc20_deposit(binary_payload)
        notice["token"] = "ERC20"
        notice["amount"] = deposit_data["amount"]
    elif header == ERC721_TRANSFER_HEADER:
        deposit_data = decode_erc721_deposit(binary_payload)
        notice["token"] = "ERC721"
        notice["token_id"] = deposit_data["token_id"]
    else:
        print("UNEXPECTED HEADER!")
        raise Exception("Unexpected HEADER.")

    notice["token_addr"] = deposit_data["token_addr"]

    if deposit_data["account"] not in accounts:
        accounts[deposit_data["account"]] = Wallet()

    account = accounts[deposit_data["account"]]
    account.deposit(deposit_data)

    return json.dumps(notice)


def decode_erc20_deposit(binary_payload):
    try:
        input_data = decode_abi(
            ['bytes32',  # Keccak256-encoded string "ERC20_Transfer"
                'address',  # Address which deposited the tokens
                'address',  # Address of the ERC-20 contract
                'uint256',  # Amount of ERC-20 tokens being deposited
                'bytes'],   # Additional data
            binary_payload
        )

        return {
            "account": input_data[1],
            "token_addr": input_data[2],
            "amount": input_data[3]
        }
    except:
        raise Exception("Error parsing ERC20 deposit.")


def decode_erc721_deposit(binary_payload):
    '''
    Retrieve the ABI-encoded input data sent by the Portal
    after an ERC-721 deposit.
        Parameters:
            binary_payload (bytes): ABI-encoded input
        Returns:
            A tuple containing:
                account (str): address of the ERC-721 token owner
                erc721 (str): ERC-721 contract address
                token_id (int): ERC-721 token ID
    '''
    try:
        input_data = decode_abi(
            ['bytes32',  # Keccak256-encoded string "ERC721_Transfer"
             'address',  # ERC-721 contract address
             'address',  # Address which called the safeTransferFrom function
             'address',  # Address which previously owned the token
             'uint256',  # The id of the NFT being deposited
             'bytes'],   # Additional data
            binary_payload
        )

        return {
            "account": input_data[3],
            "token_addr": input_data[1],
            "token_id": input_data[4]
        }
    except:
         raise Exception("Error parsing ERC721 deposit.")


def process_withdraw(msg_sender, payload):
    if msg_sender not in accounts:
        raise Exception(f"{msg_sender} does not have a Wallet.")

    withdraw_data = json.loads(payload)

    account = accounts[msg_sender]
    account.withdraw(withdraw_data)

    notice = {
        "type": "withdraw",
        "token_addr": withdraw_data["token_addr"]
    }

    if "token_id" not in withdraw_data: # ERC20 Voucher
        notice["token"] = "ERC20"
        voucher_payload = TRANSFER_FUNCTION_SELECTOR + encode_abi(
            ['address', 'uint256'],
            [account, amount]
        )
    else: # ERC721 Voucher
        notice["token"] = "ERC721"
        voucher_payload = SAFE_TRANSFER_FROM_SELECTOR + encode_abi(
            ['address', 'address', 'uint256'],
            [rollup_address, sender, token_id]
        )

    voucher = {"address": withdraw_data["token_addr"], "payload": "0x" + voucher_payload.hex()}
    post("/voucher", voucher)

    return json.dumps(notice)

def handle_advance(data):
    logger.info(f"Received advance request data {data}")
    msg_sender = data["metadata"]["msg_sender"]

    payload = data["payload"]
    status = "accept"
    try:
        # input came from the Portal (deposit)
        if msg_sender == rollup_address:
            try:
                notice = process_deposit(payload)
                post("/notice", notice)
            except Exception as error:
                error_msg = f"Failed to process deposit '{payload}'. {error}"
                post("/report", error_msg)
                status = "reject"
        else: # withdraw (generates a voucher that transfer from the DApp to the user)
            try:
                notice = process_withdraw(msg_sender, payload)
                post("/notice", notice)
            except Exception as error:
                error_msg = f"Failed to process command '{payload}'. {error}"
                post("/report", error_msg)
                status = "reject"
    except Exception as error:
        post("/report", str(error))
        status = "reject"

    return status

def handle_inspect(data):
    logger.info(f"Received inspect request data {data}")
    logger.info("Adding report")

    payload = "{"
    if len(accounts) > 0:
        for account, wallet in accounts.items():
            payload += f"{account}: {wallet},"
        payload = payload[:-1]  # remove the last ","
    payload += "}"

    payload_hex = str2hex(payload)
    response = requests.post(rollup_server + "/report", json={"payload": payload_hex})
    logger.info(f"Received report status {response.status_code}")
    return "accept"

handlers = {
    "advance_state": handle_advance,
    "inspect_state": handle_inspect,
}

finish = {"status": "accept"}
rollup_address = None

while True:
    logger.info("Sending finish")
    response = requests.post(rollup_server + "/finish", json=finish)
    logger.info(f"Received finish status {response.status_code}")
    if response.status_code == 202:
        logger.info("No pending rollup request, trying again")
    else:
        rollup_request = response.json()
        data = rollup_request["data"]
        if "metadata" in data:
            metadata = data["metadata"]
            if metadata["epoch_index"] == 0 and metadata["input_index"] == 0:
                rollup_address = metadata["msg_sender"]
                logger.info(f"Captured rollup address: {rollup_address}")
                continue
        handler = handlers[rollup_request["request_type"]]
        finish["status"] = handler(rollup_request["data"])
