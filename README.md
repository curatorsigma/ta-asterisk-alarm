# ta-asterisk-alarm
This small service reads Packets sent via COE from a CMI and then tells an asterisk server to make outgoing calls.
This is useful if you want to have alterting by phone based on physical data, such as Doorcontacts or a fire alarm.

# Getting Started
## Asterisk - Dialplan
You will want an extension in your dialplan that defines what happens in the outgoing call (such as playing audio):
```
; /etc/asterisk/extensions.conf
[commands]
exten => alarm,1,NoOp()
same => n,Playback(tt-monkeys)
same => n,Hangup()
```

## Asterisk - TLS certs
We will use AMI over TLS (AMI without TLS is NOT supported by this service.
If you have a special internal PKI or access to Lets-encrypt or another publically trusted TLS CA, you will know how to get a signed server cert for asterisk; skip this section.

To get started with self-signed certificates, do the following. I assume:
- you are the user running asterisk, called asterisk
- you can sudo
```
sudo mkdir -p /etc/ssl/asterisk/

# create a Root CA certificate
# Change the Location parts of the -subj argument
sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/ssl/asterisk/ca_key.pem -out /etc/ssl/asterisk/ca_cert.pem -days 365 -nodes -subj "/C=US/ST=SomeState/L=SomeCity/O=SomeOrg/OU=SomeUnit/CN=Asterisk Root Cert"

# Create a Private key for asterisk
sudo openssl genpkey -algorithm RSA -out /etc/ssl/asterisk/server_key.pem

# Create a CSR from the private key
# make sure to change th CN part of the subj argument and the subjectAltName to the DNS name of your asterisk server.
sudo openssl req -new -key /etc/ssl/asterisk/server_key.pem -out /etc/ssl/asterisk/server_csr.csr -nodes -subj "/C=US/ST=SomeState/L=SomeCity/O=SomeOrg/OU=SomeUnit/CN=asterisk.example.com" -addext "subjectAltName=DNS:asterisk.example.com"

# sign the CSR with the root CA cert
sudo openssl req -days 365 -in /etc/ssl/asterisk/server_csr.csr -CA /etc/ssl/asterisk/ca_cert.pem -CAkey /etc/ssl/asterisk/ca_key.pem -out /etc/ssl/asterisk/server_cert.pem -copy_extensions copy -addext "basicConstraints=CA:false"

# asterisk needs to be able to read the server private key and server cert
sudo chown asterisk /etc/ssl/asterisk/server_key.pem
sudo chown asterisk /etc/ssl/asterisk/server_cert.pem
```

You will now need to copy `/etc/ssl/asterisk/ca_cert.pem` to the machine running this service - I assume the location `/etc/ssl/ta-asterisk-alarm/asterisk_ca_cert.pem`

## Asterisk - AMI
Next, you will want to allow AMI.
Add something like this to your `/etc/asterisk/manager.conf`:
```
; /etc/asterisk/manager.conf
[general]
enabled = yes
port = 5038
; we do NOT want to listen for AMI / TCP on a public interface at all.
bindaddr = 127.0.0.1

; enable AMI/TLS
tlsenable = yes
; we DO want to listen publically for AMI/TLS
; set the address of the interface that should accept AMI here
tlsbindaddr = 0.0.0.0
; NOTE: this assumes the cert locations from above
tlscertfile = /etc/ssl/asterisk/server_cert.pem
tlsprivatekey = /etc/ssl/asterisk/server_key.pem
tlscipher = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384

[ta-asterisk-alarm]
; set your own secret. You may use `openssl rand -base64 21` or similar.
secret = NOT_THE_SECRET
deny = 0.0.0.0/0.0.0.0
; set the host (or subnet) you will run this service in.
permit = 192.168.1.123/255.255.255.255

; this user may only originate calls and nothing else
write = originate
```

## Start this service
- Copy the `config.example.yaml` to `/etc/ta-asterisk-alarm/config.yaml`.
- Create the service with `docker compose up`.
    - NOTE: this assumes that you have the CA cert on your machine in `/etc/ssl/ta-asterisk-alarm/`. Change the bind location in compose.yaml if you need this changed.

## TA - setup your CMI to send to the service
Setup a Digital output in the `Output -> COE -> Digital output` section.
The value NEEDS to be Digital ON/OFF, `unit-id` 43.

# License
This project is licensed under MIT-0 (MIT No Attribution).
By contributing to this repositry, you agree that your code will be licensed as MIT-0.

For my rationale for using MIT-0 instead of another more common license, please see
https://copy.church/objections/attribution/#why-not-require-attribution .

