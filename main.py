import sys
from phe import paillier
from electionBoard import ElectionBoard
from bulletinBoard import BulletinBoard
import utilities
def main():

    # initialize election
    numCandidates = getInt("How many candidates are there? ")
    
    if numCandidates < 2:
        print("Number of candidates is too low!")
        sys.exit()
    #This controls the number of iterations for the ZKP
    t = 3
    
    EM = ElectionBoard()
    public_key = EM.public_key
    BB = BulletinBoard(EM, numCandidates)

    #Register all the voters
    mac_ukey,mac_rkey = utilities.createRSAkeys()
    rsa_ukey = EM.startRegistration(mac_ukey)
    while True:

        voterID = getInt("\nPlease enter a voter registration number: (-1 to end registration) ")
        if voterID < 0:
            # end registration
            break
        #TODO:Encrypt voterID with private key
        #Encrypt voterID with EM public key
        ctxt = utilities.rsaEncrypt(rsa_ukey,voterID)
        #Send to EM
        EM.register(ctxt)
        
        
    # collect votes until voting ends
    while True:

        # TODO: encrypt voter number
        voterID = getInt("\nPlease enter your voter registration number(-1 to end voting): ")
        if voterID < 0:
            #end voting
            break
        if (not EM.checkRegistration(voterID)):
            continue
        print("Candidate choices: " + str([i for i in range(numCandidates)]))
        voteIndex = getInt("Please enter your vote: ")

        if voteIndex >= numCandidates or voteIndex<0:
            print ("Invalid vote!")
            continue

        vote = [0 for i in range(numCandidates)]
        vote[voteIndex] = 1
        
        # get vote signed by EM
        signedVote = EM.signVote(vote)
        

        ctxts = [0 for i in range(numCandidates)]
        allowVote=False
        print("Sending vote...")
        #ZKP occurs for each candidate in the vote
        while not allowVote:
            allowVote=True
            for i in range(numCandidates):
                c,x = utilities.palEncrypt(public_key,vote[i])
                for iter in range(0,t):
                    u,r,s = utilities.palEncryptRan(public_key)
                    e = BB.sendVote(c,u)
                    v,w = utilities.answerChallenge(public_key,vote[i],e,x,r,s)
                    if (not BB.sendAnswer(v,w)):
                        print("Vote has been tampered with, Trying to send again...")
                        allowVote=False
                        break
                    ctxts[i] = c
                if not allowVote:
                    break
            if allowVote:
                BB.addVote(ctxts)
                
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
