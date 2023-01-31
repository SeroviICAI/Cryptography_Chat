# Cryptography_Chat
## Description
This is an encrypted local messaging app. The objective behing this project was implementing RSA in Python. Uses a modular arithmetic library created by my own, "modular.py". This is an educational project done in college.

## How to run
Run criptochat.py in your computer.

## User Interface
![ui app](https://github.com/SeroviICAI/Cryptography_Chat/blob/master/images/screenshot_crypto.PNG)

## Notes
This program is a local encrypted chat between users. It also serves that a user can decrypt with his private key messages encrypted with his key public. Within this program you can perform the following functions:
- Register new users.
- Log in with a registered user.
- Change the number of padding digits with which the user encrypts and decrypt the messages.
- Show registered users.

Once logged in with an existing user, the following are enabled: functions:
- Look at the inbox1 of a user (decryption).
- Send a message to another registered user.
- Show the public and private keys of the user.
- Change user passwords.
- Decrypt a message encrypted with the user's public key.
- Sign off.
For some of these functions, the client will need to know the identifier of your user.

In both instances you can safely exit the process. The program will always try to save changes made to users in a users.dat file located in the data folder. You can't always do it when there is a problem in the writing process of this file, it is “kill” the process externally or the program ends its execution for a unexpected/unhandled error. The program is designed with the intention that it remains operational against all kinds of errors.

## More information
Read code documentation and pdf (in spanish)
