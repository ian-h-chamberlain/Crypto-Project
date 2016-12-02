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

    def sendVote(self,vote,signature):
        # now verify signature of vote
        if not utilities.verify(vote, signature, self.electionBoard.rsa_pub):
            print ("Vote is not signed by the authority! discounting")
            return
        ''' verify each vote is only for one candidate
            verification strategy:
            Randomly permute the vote array
            Send to EM 
            EM checks each value is 0 or 1 and the sum is 1
            Also ensure there are a correct number of candidates
        '''
        permute = utilities.permute(vote)
        if not self.electionBoard.checkValidity(permute):
            print("Invalid vote detected!")
            return # cannot count this vote
        if len(vote) != self.numCandidates:
            print("Invalid vote detected!")
            return # cannot count this vote

        self.temp_vote = vote
    def createChallenge(self,u,i):
        self.u = u
        self.c = self.temp_vote[i]
        self.e = utilities.makeChallenge(self.A)
        return self.e
    def sendAnswer(self,v,w):
        return utilities.checkChallenge(self.public_key,self.u,self.e,self.c,v,w)
    def acceptVote(self):
        self.voteBoard.append(self.temp_vote)

    def tallyResults(self):

        # initialize the total
        totals = [0 for i in range(self.numCandidates)]
        #Encrypt the 0s for summing
        for i in range(len(totals)):
            totals[i],_ = utilities.palEncrypt(self.electionBoard.public_key,0)

        # now actually tally the votes
        for vote in self.voteBoard:
            for i in range(len(vote)):
                totals[i] = totals[i]*vote[i]

        # report results to EM
        self.electionBoard.reportResults(totals)
