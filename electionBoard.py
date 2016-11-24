from phe import paillier

# ElectionBoard - contains code for managing voters and results

class ElectionBoard:

    def __init__(self):
        self.public_key, self.private_key = paillier.generate_paillier_keypair()
        self.registeredVoters = []
        self.signature = "SIGNED"

    # check if the voter has registered/voted yet, and sign their vote if not
    def registerVote(self, voterID, vote):

        # we may need to split this if we're required to separate registration from voting
        if voterID not in self.registeredVoters:
            self.registeredVoters.append(voterID)
            return self.signVote(vote)
        else:
            print("Voter tried to register twice!")
            return None

    # apply a signature to the vote and send it back
    def signVote(self, vote):
        res = []
        for i in vote:
            #TODO: encrypt votes with blind signature
            res.append(self.public_key.encrypt(i))
        return res

    # get encrypted totals and report them
    def reportResults(self, encrypted_results):
        # TODO: decrypt totals

        results = [self.private_key.decrypt(x) for x in encrypted_results]

        index = -1
        total = -1
        for i in range(len(results)):
            if total < results[i]:
                index = i
                total = results[i]

        # TODO: show ties, maybe?
        print("Candidate " + str(index) + " wins!")
        print("Vote breakdown:")
        for i in range(len(results)):
            print("\tCandidate " + str(i) + ": " + str(results[i]) + " votes")
