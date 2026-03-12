from enum import Enum

class Network(Enum):
    mainnet = -239
    testnet = -3
    
    def chain_id(self):
        return self.value
