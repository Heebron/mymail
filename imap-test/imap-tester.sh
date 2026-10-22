#!/bin/bash

# https://github.com/dovecot/imaptest

LOGIN="host=mymail.thepratts.info port=993 user=tester pass=changeit ssl=any-cert mech=plain stalled_disconnect_timeout=10 mbox=/data/dovecot-crlf"

#docker run --rm -it -v ./volume:/data:ro dovecot/imaptest $LOGIN
#docker run --rm -it -v ./volume:/data:ro dovecot/imaptest $LOGIN test=/data/rfc-compliance.script

docker run --rm -it -v ./volume:/data:ro dovecot/imaptest $LOGIN clients=1 fetch2=10 store=10 delete=10
