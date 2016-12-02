

# ElectionBoard - contains code for managing voters and results
from phe import paillier
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import utilities
class ElectionBoard:

    def __init__(self):
        self.rsa_priv = RSA.generate(1024)
        self.rsa_pub = self.rsa_priv.publickey()
        self.registeredVoters = []
        self.votedVoters = []
        self.totals = []
        self.signature = "SIGNED"
        self.public_key,self._private_key = paillier.generate_paillier_keypair()


    #Prepares keys for registration
    def startRegistration(self,mac_ukey):
        self.mac_ukey = mac_ukey
        ukey,self._rsa_rkey =utilities.createRSAkeys()
        return ukey
    # check if the voter has registered yet
    def registerVote(self, voterID):
        if voterID not in self.registeredVoters:
            self.registeredVoters.append(voterID)
            return True
        print("This voter is already registered!")
        return False
    #Register a new voter
    def register(self,cID,signature):
        #Decrypt voterID
        voterID = utilities.rsaDecrypt(self._rsa_rkey,cID)
        #Verify using public mac key
        if not utilities.rsaVerify(self.mac_ukey,voterID,signature):
            print("Registration is not from a verified source. Ignoring...")
            return False
        return self.registerVote(voterID)
    
    #Check to make sure voter is registered and hasn't already voted
    def checkRegistration(self,cID):
        #Decrypt voterID
        voterID = utilities.rsaDecrypt(self._rsa_rkey,cID)
        #Check if voter is registered
        if voterID in self.registeredVoters:
            if voterID not in self.votedVoters:
                self.votedVoters.append(voterID)
                return True
            else:
                print("This voter has already voted")
        else:
            print("This voter did not register")
        return False

    # apply a signature to the vote and send it back
    def signVote(self, vote):
        # test to make sure votes were blinded properly
        v = self.rsa_priv.sign(vote, 0) # NOTE: 0 maybe should be changed to something else
        return v[0] # the signature is in the first part

    # Checks the validity of a randomly permuted vote list
    def checkValidity(self,votes):
        
        total = 0
        for i in votes:
            # i[1] contains the encrypted vote
            v = utilities.palDecrypt(self._private_key,i)
            total+=v
            if v!=0 and v!=1:
                return False
            
        return total==1

    # get encrypted totals and report them
    def reportResults(self, results):
        # Decrypt totals
        self.totals = [utilities.palDecrypt(self._private_key,x) for x in results]

