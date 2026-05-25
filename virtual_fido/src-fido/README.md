# setup

cd ctap_proxy

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

# use the virtual 

sudo venv/bin/python3.12 -m virtual_fido

# use the real one
(need to have the real device usb plugged)

sudo venv/bin/python3.12 -m virtual_fido -r

# use the man in the middle (just does a simple attack)
(need to have the real device usb plugged)

It bypasses the browser pin security letting a user authenticate without needing to insert the right PIN. Its not possible to create a credential, it needs to be created earlier with the token

sudo venv/bin/python3.12 -m virtual_fido -m

The file client_lib is only needed to apply the MiTM so that the script behaves as a client to a real authenticator
# test

https://webauthn.io/

fido2-token -L

fido2-token -I /dev/hidrawX

sudo hexdump -C /dev/hidrawX 

