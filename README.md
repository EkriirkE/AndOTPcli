Requires the python package `pyotp`

Use the AndOTP bakup option, with the type of Encrypted.  Choose a password for it and save it in a location you can retrieve it from (e.g. upload to a drive service, email to yourself, etc)

Save the file as "authenticator.json.aes" in the same folder this script runs in.

Run the script

$ python authenticator.py

Enter the password you saved the backup as

You will be prompted with a live list of OTP accounts, the current code, and a timer at the bottom.

    0	  Reddit	696969	EkriirkE
    1	 Discord	777777
    2	  Paypal	888888	EkriirkE
    3	 Twitter	123456	@LEDSuit
    
    Next refresh in 42...

If you press the case-sensitive letter of the OTP item, you will be presented iwth a QR code to scan and import into another OTP app.
 - This requires the local system package `qrencode` to be installed

Press Ctrl-C to exit.
