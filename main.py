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

                BB.addVote(ctxts, unblind)
                
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
