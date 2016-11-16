import sys
from electionBoard import ElectionBoard
from bulletinBoard import BulletinBoard

def main():

    # initialize election
    numCandidates = getInt("How many candidates are there? ")
    
    if numCandidates < 2:
        print("Number of candidates is too low!")
        sys.exit()

    EM = ElectionBoard()
    BB = BulletinBoard(EM, numCandidates)

    # collect votes until voting ends
    while True:

        # TODO: encrypt voter number
        voterID = getInt("\nPlease enter your voter registration number: ")
        # may also need to register voter before actually voting

        # TODO: encrypt votes
        print("Candidate choices: " + str([i for i in range(numCandidates)]))
        voteIndex = getInt("Please enter your vote (-1 to end voting): ")

        if voteIndex < 0:
            # end voting
            break

        if voteIndex >= numCandidates:
            print ("Invalid vote!")
            continue

        vote = [0 for i in range(numCandidates)]
        vote[voteIndex] = 1

        # get vote signed by EM
        signedVote = EM.registerVote(voterID, vote)
        
        if signedVote != None:
            BB.addVote(signedVote)

    # now total and display the results
    BB.tallyResults()

# get integer command line input - this can be update to use GUI later
def getInt(prompt):
    while (True):
        print(prompt)
        try:
            response = input().strip()
            result = int(response)
        except (ValueError, EOFError):
            print("Invalid input!")
            continue
        break

    return result

if __name__ == "__main__":
    main()
