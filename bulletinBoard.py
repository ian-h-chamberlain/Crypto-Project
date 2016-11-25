from Crypto.Hash import SHA256 
from phe import paillier

# BulletinBoard - tally votes and send results to EM

class BulletinBoard:

    def __init__(self, em, numCandidates):
        # initialize the vote board
        self.numCandidates = numCandidates
        self.voteBoard = []
        self.electionBoard = em

    def addVote(self, vote):

        # first, verify signature of vote
        for v in vote:
            sha = SHA256.new(str(v[1]).encode()) # get hash of encrypted vote
            if not self.electionBoard.rsa_pub.verify(sha.digest(), (v[0],)):
                print ("Vote tampered with! discounting")
                return

        # verify each vote is only for one candidate
        total = 0

        for i in vote:
            total = total + i[1]    # for now just use second part of tuple

        # TODO: engage ZKP
        #if total != 1:
            #print("Invalid vote detected!")
            #return # cannot count this vote

        self.voteBoard.append(vote)

    def tallyResults(self):

        # initialize the total
        totals = [0 for i in range(self.numCandidates)]

        # now actually tally the votes
        for vote in self.voteBoard:
            for i in range(len(vote)):
                paillierVote = paillier.EncryptedNumber(self.electionBoard.paillier_pub, vote[i][1])
                totals[i] = totals[i] + paillierVote

        # report results to EM
        self.electionBoard.reportResults([i.ciphertext() for i in totals])
