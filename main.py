import tkinter as tk
import time
import sys
from electionBoard import ElectionBoard
from bulletinBoard import BulletinBoard
from tkinter import messagebox
import utilities

# First window
def AskCandidates():
    '''
        Welcome window for the Election program,
        prompts user for the number of candidates
        using an Entry and submits value using the
        button. 
    '''
    
    # Create window
    window = tk.Toplevel(root)
    window.protocol("WM_DELETE_WINDOW", OnClosing)
    window.geometry("300x90")
    center(window)

    # Format window
    window.title("Welcome!")
    label = tk.Label(window, text='How many canididates are there?', font=('Helvetica', 14))
    label.pack()
    ent = tk.Entry(window)
    ent.pack()
    tk.Button(window,text="Enter",command=lambda: RegisterVoter(int(ent.get()), window)).pack()

# Second window
def RegisterVoter(numCandidates, old_window):
    '''
        Processes the candidate value and makes sure
        it is valid, if so create the voter registration
        window and prompt them for their registration
        number. 	
    '''
    
    # Require 2 or more candidates
    if(numCandidates >= 2):
        vote = [0 for i in range(numCandidates)]
        EM = ElectionBoard()
        BB = BulletinBoard(EM, numCandidates)
        
        #Register all the voters
        mac_ukey,mac_rkey = utilities.createRSAkeys()
        rsa_ukey = EM.startRegistration(mac_ukey)
	
        # Create new window
        old_window.destroy()
        window = tk.Toplevel(root)
        window.protocol("WM_DELETE_WINDOW", OnClosing)
        window.geometry("330x100")
        center(window)
	
        # Format window
        window.title("Voter Registration")
        tk.Label(window, text='Please enter a voter registration number', font=('Helvetica', 14)).pack()
        tk.Label(window, text='(Enter -1 to end registration and begin voting)').pack()
        ent = tk.Entry(window)
        ent.pack()
        tk.Button(window,text="Enter", command=lambda:	StartVoting(int(ent.get()), ent, vote, EM, BB, mac_rkey, rsa_ukey, window)).pack()
    else: 
        # Creates an error message if invalid candidates
        tk.Label(old_window, text='Need more than 1 candidate', fg='red').pack()

# Third window
def StartVoting(voterID, ent, vote, EM, BB, mac_rkey, rsa_ukey, old_window):
    '''
        Asks voter for their registration number,
        if successful window opens to vote for their 
        candidate. 		
    '''
    
    if(voterID == -1):
        # Create window
        old_window.destroy()
        window = tk.Toplevel(root)
        window.protocol("WM_DELETE_WINDOW", OnClosing)
        window.geometry("360x90")
        center(window)
        
    	# Format window
        window.title("Voting Time!")	
        tk.Label(window, text='Please enter a voter registration (-1 to end)', font=('Helvetica', 14)).pack()
        ent = tk.Entry(window)
        ent.pack()
        tk.Button(window, text='Next', command=lambda: SendVote(int(ent.get()), vote, EM, BB, rsa_ukey, window)).pack()
    else:
        ent.delete(0, "end")

        #Sign voterID with private mac key
        signature = utilities.rsaSign(mac_rkey,voterID)

        #Encrypt voterID with EM public key
        ctxt = utilities.rsaEncrypt(rsa_ukey,voterID)

        #Register with EM
        EM.register(ctxt,signature)

# Fourth window
def SendVote(voterID, vote, EM, BB, rsa_ukey, old_window):
    '''
        Prompts the user to vote for their 
        candidate otherwise if voting has 
        ended it will show the winner of 
        the election.
    '''
    numCandidates = len(vote)
    if(voterID == -1):
        # Gets total counts for all candidates
        BB.tallyResults()

        # Gets candidate who won
        winner = findWinner(EM.totals)

        # Display Winner
        old_window.destroy()
        window = tk.Toplevel(root)
        window.protocol("WM_DELETE_WINDOW", OnClosing)
        window.geometry("250x200")
        center(window)

        window.title('Results')
        tk.Label(window, text='Candidate '+str(winner)+' Wins!', fg='green', font=('Helvetica', 18)).pack()
        for i in range(len(EM.totals)):
            tk.Label(window, text='Candidate '+ str(i) +': '+ str(EM.totals[i]) + ' votes').pack()

        tk.Button(window, text='Close', command=lambda: CloseWindows(window)).pack(side=tk.BOTTOM)	
    else:
        ctxt = utilities.rsaEncrypt(rsa_ukey,voterID)
        if (EM.checkRegistration(ctxt)):
            # Vote for candidate
            old_window.destroy()
            window = tk.Toplevel(root)
            window.protocol("WM_DELETE_WINDOW", OnClosing)
            window.geometry("220x140")	
            center(window)

            window.title("Cast Vote")
            tk.Label(window, text='Candidate Choices', font=('Helvetica', 18)).pack()
            tk.Label(window, text=str([i for i in range(numCandidates)])).pack()
            tk.Label(window, text='Please enter your vote').pack()
            ent = tk.Entry(window)
            ent.pack()
            tk.Button(window, text='Vote', command=lambda: NextVoter(int(ent.get()), vote, EM, BB, rsa_ukey, window)).pack()

# Prompts user again for their voter registration number
def NextVoter(voteIndex, vote, EM, BB, rsa_ukey, old_window):
    numCandidates = len(vote) 

    # Iterations for ZKP
    t = 3
    if not (voteIndex >= numCandidates or voteIndex < 0):
        vote[voteIndex] = 1

        #Encrypt vote and store the random numbers for ZKP
        ctxts = [0 for i in range(numCandidates)]
        xs = [0 for i in range(numCandidates)]
        for i in range(numCandidates):
            ctxts[i],xs[i] = utilities.palEncrypt(EM.public_key,vote[i])

        #Encrypt vote and store the random numbers for ZKP
        ctxts = [0 for i in range(numCandidates)]
        xs = [0 for i in range(numCandidates)]
        for i in range(numCandidates):
            ctxts[i],xs[i] = utilities.palEncrypt(EM.public_key,vote[i])
        
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

        #ZKP occurs for each candidate in the vote
        allowVote=False
        ZKP_LIMIT = 15
        zkp_iter = 0
        t0 = time.time()
        while not allowVote:
            BB.sendVote(ctxts,unblind)
            allowVote=True
            for i in range(numCandidates):
                c = ctxts[i]
                x = xs[i]
                for iter in range(0,t):
                    u,r,s = utilities.palEncryptRan(EM.public_key)
                    e = BB.createChallenge(u,i)
                    v,w = utilities.answerChallenge(EM.public_key,vote[i],e,x,r,s)
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
        t1 = time.time()
        print(t1-t0)

        old_window.destroy()
        window = tk.Toplevel(root)
        window.protocol("WM_DELETE_WINDOW", OnClosing)
        window.geometry("360x90")
        center(window)
        window.title("Voting Time!")
    	
        tk.Label(window, text='Please enter a voter registration (-1 to end)', font=('Helvetica', 14)).pack()
        ent = tk.Entry(window)
        ent.pack()

        vote = [0 for i in range(numCandidates)]
        tk.Button(window, text='Next', command=lambda: SendVote(int(ent.get()), vote, EM, BB, rsa_ukey, window)).pack()

# Closes all windows
def CloseWindows(old_window):
    old_window.destroy()
    root.destroy()

# Asks user if they want to quit and terminates program if yes
def OnClosing():
    if(tk.messagebox.askokcancel('Exit', 'Do you want to quit?')):
        root.destroy()

# Finds winner in the total tally for votes
def findWinner(totals):
    index = -1
    total = -1
    for i in range(len(totals)):
        if total < totals[i]:
            index = i
            total = totals[i]
    return index


# Centers the Tkinter window
def center(toplevel):
    toplevel.update_idletasks()
    size = tuple(int(_) for _ in toplevel.geometry().split('+')[0].split('x'))
    x = (toplevel.winfo_screenwidth() / 2) - (size[0] / 2)
    y = (toplevel.winfo_screenheight() / 2) - (size[1] / 2)
    toplevel.geometry("%dx%d+%d+%d" % (size + (x, y)))

if __name__ == "__main__":
    root = tk.Tk()

    # Minimizes the root window
    root.iconify()

    # Handles user closing window via 'X'
    root.protocol("WM_DELETE_WINDOW", OnClosing)
    
    AskCandidates()
    root.mainloop()
