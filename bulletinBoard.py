import math
import utilities
# BulletinBoard - tally votes and send results to EM

class BulletinBoard:

    def __init__(self, em, numCandidates):
        # initialize the vote board
        self.numCandidates = numCandidates
        self.voteBoard = []
        self.electionBoard = em
        self.public_key = em.public_key
        self.A = int(math.log(self.public_key.n))**100
    def sendVote(self,ctxt,u):
        self.temp_ctxt = ctxt
        self.u = u
        self.e = utilities.makeChallenge(self.A)
        return self.e
    def sendAnswer(self,v,w):
        return utilities.checkChallenge(self.public_key,self.u,self.e,self.temp_ctxt,v,w)
    def addVote(self, vote):
        n2 = self.public_key.n**2
        
        # verify each vote is only for one candidate
        #TODO: verify each vote is either 0 or 1
        total = 0

        for i in vote:
            if total==0:
                total = i
            else:
                total = total*i%n2

        if not self.electionBoard.checkValidity(total):
            print("Invalid vote detected!")
            return # cannot count this vote

        self.voteBoard.append(vote)

    def tallyResults(self):

        # initialize the total
        totals = [0 for i in range(self.numCandidates)]

        # now actually tally the votes
        for vote in self.voteBoard:
            for i in range(len(vote)):
                if totals[i]==0:
                    totals[i] = vote[i]
                else:
                    totals[i] = totals[i]*vote[i]

        # report results to EM
        self.electionBoard.reportResults(totals)
