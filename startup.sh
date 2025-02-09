#!/bin/bash

#DEPOT=/depot
PKCS11CONF=${DEPOT}/pkcs11-config.json
AWSKMSCONF=${DEPOT}/aws-kms-config.json
#REGION=eu-west-1

# things to grab from environment variables
# see https://github.com/PortSwigger/scep-pkcs11/blob/main/cmd/scepserver/scepserver.go#L47 for more details
# SCEP_CA_PASS
# SCEP_FILE_DEPOT
# SCEP_HTTP_LISTEN_PORT
# SCEP_CERT_RENEW
# SCEP_CHALLENGE_PASSWORD
# SCEP_PKCS11_CONFIGFILE
# SCEP_LOG_JSON (bool)
# SCEP_LOG_DEBUG (bool)
# 
# things that should exist in ssm parameter store and be available to us via env variables
#SM_PKCS11_CONF=""     # an ARN of the config used by scepserver -pkcs11-config argument
#SM_KMS_CONFIG=""      # an ARN of the config file used by the pkcs11 shim to be stored in /etc/aws-kms-pkcs11/config.json

# expose as ENV var
#SM_CMD_SECRETS_ARN=""

# takes secret arn, secret name. returns just the secret.
getsecretvalue() {
        aws ssm get-parameter --name $1 --with-decryption |  jq --raw-output '.Parameter.Value'
}

# takes secretarn, filename to write contents to
getsecretblob() {
        aws ssm get-parameter --name $1 --region=${REGION} | jq --raw-output '.Parameter.Value' > $2
        echo grabbing $1 saving to $2
}

# First up, check to see if our pkcs11 config file exists, and grab it if not.
# if [ ! -f ${PKCS11CONF} ]; then
#         getsecretblob ${SM_PKCS11_CONF} ${PKCS11CONF}
# fi
getsecretblob ${SM_PKCS11_CONF} ${PKCS11CONF}
# next, we need to grab our aws-kms-pkcs11 config.
# this test is redundant but makes it look pretty :-)
# if [ ! -f /etc/aws-kms-pkcs11/config.json ]; then
#         mkdir -p /etc/aws-kms-pkcs11/
#         getsecretblob ${SM_KMS_CONFIG} /etc/aws-kms-pkcs11/config.json
# fi

getsecretblob ${SM_KMS_CONFIG} ${AWSKMSCONF}

CAPASS=`getsecretvalue $SCEP_CA_PASS`
CHALLENGE=`getsecretvalue $SCEP_CHALLENGE_PASSWORD`

# comment when not broken... uncomment when you want to 'start afresh'.
#rm -f ${DEPOT}/ca.key ${DEPOT}/index.txt ${DEPOT}/*.pem ${DEPOT}/serial

# at this point we have the aws-kms-pkcs11 config in place, and our pkcs11-config.json in place.
# However we might have never ran before, so assuming so let's check to see if we have a ca.key
# on the block storage.
if [ ! -f ${DEPOT}/ca.key ]; then
        # init ca
        echo "Seems like first bootup - creating on disk CA"
        /usr/bin/scepserver ca -init -pkcs11-config ${PKCS11CONF} -depot ${DEPOT} --key-password $CAPASS || exit 1
fi

# get real cert
rm -f -- ${DEPOT}/external-ca.pem
getsecretblob ${SCEP_CA_CERT} ${DEPOT}/external-ca.pem

# we should be able to start now.
echo "attempting to start server"
cat ${PKCS11CONF} ${AWSKMSCONF} ${DEPOT}/external-ca.pem
/usr/bin/scepserver -capass $CAPASS -challenge $CHALLENGE -depot $DEPOT -pkcs11-config ${PKCS11CONF} -debug -allowrenew 0
