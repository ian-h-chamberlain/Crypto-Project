
# BulletinBoard - tally votes and send results to EM

class BulletinBoard:

    def __init__(self, em, numCandidates):
        # initialize the vote board
        self.numCandidates = numCandidates
        self.voteBoard = []
        self.electionBoard = em

    def addVote(self, vote):

        # verify each vote is only for one candidate
        total = 0

        for i in vote:
            total = total + i    # for now, just use second part of tuple

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
                totals[i] = totals[i] + vote[i]

        # report results to EM
        self.electionBoard.reportResults(totals)
