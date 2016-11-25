import sys
from phe import paillier
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import Crypto.Random
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
        # TODO: also need to register voter before actually voting

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

        # now blind the votes before sending to EM to sign
        blindVote = []
        rlist = []
        encVote = []

        rng = Crypto.Random.new()

        # use the EM's public key for blind signatures

        for i in vote:
            v = EM.paillier_pub.encrypt(i).ciphertext()
            encVote.append(v)
            # need to hash b/c paillier encrypted is too long
            sha = SHA256.new(str(v).encode())

            rlist.append(rng.read(64)) # pick a 64-byte random blinding factor
            blindVote.append(EM.rsa_pub.blind(sha.digest(), rlist[-1]))

        # get vote signed by EM
        signedVote = EM.registerVote(voterID, blindVote)
        unblindVote = []

        # make sure we got a real result from signing
        if signedVote != None:
            # now need to unblind message
            for i in range(len(signedVote)):
                v = EM.rsa_pub.unblind(signedVote[i], rlist[i])
                unblindVote.append((v, encVote[i]))

            BB.addVote(unblindVote)

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
