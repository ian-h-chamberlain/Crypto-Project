# Crypto-Project

This is a simple voting application which is designed to ensure secure voter anonymity while preventing fraudulent votes.

## Setup and Usage
Dependencies:
- [pycrypto](https://www.dlitz.net/software/pycrypto/)
- [python-paillier](https://python-paillier.readthedocs.io/)
- [Kivy](https://kivy.org/)

To run, simply execute `python main.py`.

## Implementation details:
### Main – `main.py`
This handles the user interaction and encrypts the user's vote before sending it to any other component. It requests voter registration verification from the Election Board and sends a signed, encrypted vote to the Bulletin Board to be counted. A Zero-Knowledge Proof is used to ensure that the correct vote is registered with the Bulletin Board.

### Election Board – `electionBoard.py`
The Election Board is responsible for verifying voter registration and signs votes to validate their authenticity. It also takes encrypted results from the Bulletin Board and decrypts them to announce the winner of the election.

### Bulletin Board - `bulletinBoard.py`
The Bulletin Board receives and holds encrypted votes from each voter. Because Paillier encryption is used, the votes can be added together to obtain an encrypted total, which is then sent to the Election Board to be decrypted and revealed.
