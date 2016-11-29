# ElectionBoard - contains code for managing voters and results
from phe import paillier
from Crypto.Cipher import PKCS1_OAEP
import utilities
class ElectionBoard:

    def __init__(self):
        self.registeredVoters = []
        self.votedVoters = []
        self.signature = "SIGNED"
        self.public_key,self._private_key = paillier.generate_paillier_keypair()

    def startRegistration(self,mac_ukey):
        self.mac_ukey = mac_ukey
        ukey,self._rsa_rkey =utilities.createRSAkeys()
        return ukey
    # check if the voter has registered/voted yet
    def registerVote(self, voterID):
        if voterID not in self.registeredVoters:
            self.registeredVoters.append(voterID)
            return True
        print("This voter is already registered!")
        return False

    #Register a new voter
    def register(self,cID):
        #Decrypt voterID
        voterID = utilities.rsaDecrypt(self._rsa_rkey,cID)
        #TODO: Decrypt using public mac key
        #TODO:cryptographically hash voterID
        
        return self.registerVote(voterID)
    #Check to make sure voter is registered and hasn't already voted
    def checkRegistration(self,cID):
        #TODO: Decrypt voterID
        voterID = cID
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
        res = []
        for i in vote:
            #TODO: encrypt votes with blind signature
            res.append((self.signature, i))
        return res

    # Checks the validity of the "sum" of the votes to be one
    def checkValidity(self,total):
        return utilities.palDecrypt(self._private_key,total)==1
    # get encrypted totals and report them
    def reportResults(self, results):
        # TODO: decrypt totals
        totals = [utilities.palDecrypt(self._private_key,x) for x in results]
        index = -1
        total = -1
        for i in range(len(totals)):
            if total < totals[i]:
                index = i
                total = totals[i]

        # TODO: show ties, maybe?
        print("Candidate " + str(index) + " wins!")
        print("Vote breakdown:")
        for i in range(len(totals)):
            print("\tCandidate " + str(i) + ": " + str(totals[i]) + " votes")
