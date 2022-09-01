import hashlib
from ecdsa import SigningKey, SECP112r2 #Private/Public key algorithm for signatures
import time #For timestamps
import secrets
import base64


class Transaction:
	def __init__(self, amount, payer, payee):
		self.amount = amount
		self.payer = payer
		self.payee = payee
		self.tostring = f"{self.payer} -> {self.payee} $ {self.amount}"


class Block:
	def __init__(self, prevHash, transaction):
		self.nonce = 94782 #Genesis nonce, mine() will generate a valid one for new blocks
		self.prevHash = prevHash
		self.transaction = transaction
		self.ts = 0 #Genesis timestamp, mine() will generate a valid one for new blocks
		
		self.tostring = f"T-{self.ts}$N-{str(self.nonce)}$PH-{self.prevHash} | {self.transaction.tostring}" #For genesis block, doesn't affect following blocks due to mine()
		self.hashed = hashlib.sha256(self.tostring.encode()).hexdigest() #For genesis block, doesn't affect following blocks due to mine()

	def mine(self, nonce):

		while True:
			self.ts = int(time.time())
			self.tostring = f"T-{self.ts}$N-{str(self.nonce)}$PH-{self.prevHash} | {self.transaction.tostring}"
			hashed = hashlib.sha256(self.tostring.encode()).hexdigest()

			if hashed[0:4] == "0000":

				self.tostring = f"T-{self.ts}$N-{str(self.nonce)}$PH-{self.prevHash} | {self.transaction.tostring}"
				self.hashed = hashed
				print('Succesfully mined:\n'+self.tostring+'\n')
				return hashed
				
			self.nonce += 1


class Chain:
	def __init__(self):
		self.blocks = [Block("None", Transaction(100, "genesis", "satoshi"))]

	def addBlock(self, transaction, senderPublicKey, signature):
		isValid = senderPublicKey.verify(signature, transaction.tostring.encode())

		if isValid:
			newBlock = Block(self.blocks[-1].hashed, transaction)
			newBlock.mine(newBlock.nonce)
			self.blocks.append(newBlock)
		else:
			print("INVALID") #print INVALID if using wrong signature(the library this is using might do an assertionerror by default, not sure tho)


class Wallet:
	def __init__(self):
		self.privateKey = SigningKey.generate(curve=SECP112r2)
		self.publicKey = self.privateKey.verifying_key

	def sendMoney(self, amount, payeePublicKey):
		transaction = Transaction(
			amount,
			base64.b64encode(self.publicKey.to_string()).decode(), #Base64 encoded
			base64.b64encode(payeePublicKey.to_string()).decode(),	#Base64 encoded
		)
		signature = self.privateKey.sign(transaction.tostring.encode()) #Sign the transaction
		chain.addBlock(transaction, self.publicKey, signature) #Attempt to add block to chain, remember that it will go through mine() to generate a nonce
		#Also keep in mind that "chain" is the name of the Chain() object

chain = Chain()

if __name__ == '__main__':
	chain = Chain()

	satoshi = Wallet()
	bob = Wallet()
	alice = Wallet()

	satoshi.sendMoney(50, bob.publicKey)
	bob.sendMoney(23, alice.publicKey)
	alice.sendMoney(5, bob.publicKey)

	print("\n\nBlocks:\n"+"\n\n".join([i.tostring for i in chain.blocks]))
