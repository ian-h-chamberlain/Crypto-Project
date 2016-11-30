import sys
from electionBoard import ElectionBoard
from bulletinBoard import BulletinBoard
import utilities
def main():

    # initialize election
    numCandidates = getInt("How many candidates are there? ")
    
    if numCandidates < 2:
        print("Number of candidates is too low!")
        sys.exit()
    
    EM = ElectionBoard()
    public_key = EM.public_key
    BB = BulletinBoard(EM, numCandidates)

    #Register all the voters
    mac_ukey,mac_rkey = utilities.createRSAkeys()
    rsa_ukey = EM.startRegistration(mac_ukey)
    while True:

        voterID = getInt("\nPlease enter a voter registration number (-1 to end registration): ")
        if voterID < 0:
            # end registration
            break
        #Sign voterID with private mac key
        signature = utilities.rsaSign(mac_rkey,voterID)
        #Encrypt voterID with EM public key
        ctxt = utilities.rsaEncrypt(rsa_ukey,voterID)
        #Register with EM
        EM.register(ctxt,signature)

    print("Registration is closed.")
    print("Voting begins.")

    # Collect votes until voting ends

    #This controls the number of iterations for the ZKP
    t = 3

    while True:

        voterID = getInt("\nPlease enter your voter registration number(-1 to end voting): ")
        if voterID < 0:
            #end voting
            break
        ctxt = utilities.rsaEncrypt(rsa_ukey,voterID)
        if (not EM.checkRegistration(ctxt)):
            continue
        while True:
            print("Candidate choices: " + str([i for i in range(numCandidates)]))
            voteIndex = getInt("Please enter your vote: ")
            if not (voteIndex >= numCandidates or voteIndex<0):
                break
            print ("Invalid vote! Try again")
        vote = [0 for i in range(numCandidates)]
        vote[voteIndex] = 1

        #Encrypt vote and store the random numbers for ZKP
        ctxts = [0 for i in range(numCandidates)]
        xs = [0 for i in range(numCandidates)]
        for i in range(numCandidates):
            ctxts[i],xs[i] = utilities.palEncrypt(public_key,vote[i])
        
        '''
           Blind signature process starts here

        '''
        # now blind the votes before sending to EM to sign
        blindVote, r = utilities.blind(ctxts, EM.rsa_pub)

        # get vote signed by EM
        signedVote = EM.signVote(blindVote)

        # make sure we got a real result from signing
        if signedVote != None:
            # now need to unblind message
            unblind  = EM.rsa_pub.unblind(signedVote, r)
        print("Sending vote...")
        
        #ZKP occurs for each candidate in the vote
        allowVote=False
        ZKP_LIMIT = 15
        zkp_iter = 0
        while not allowVote:
            BB.sendVote(ctxts,unblind)
            allowVote=True
            for i in range(numCandidates):
                c = ctxts[i]
                x = xs[i]
                for iter in range(0,t):
                    u,r,s = utilities.palEncryptRan(public_key)
                    e = BB.createChallenge(u,i)
                    v,w = utilities.answerChallenge(public_key,vote[i],e,x,r,s)
                    if (not BB.sendAnswer(v,w)):
                        print("Vote has been tampered with, Trying to send again")
                        allowVote=False
                        break
                if not allowVote:
                    break
            zkp_iter+=1
            if zkp_iter>ZKP_LIMIT:
                break
        if allowVote:
            BB.acceptVote()
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
