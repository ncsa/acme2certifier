<!-- markdownlint-disable  MD013 -->
<!-- wiki-title CA trigger -->
# Ca_handler.trigger()

The ```trigger``` method allows a CA server to invoke certain actions on acme2certifier. The actions to be executed will be
defined by the respective CA handler. This method as been implemented to cover use-cases in which a CSR goes into pending state and CA server as the ability to trigger scripts
after CSR approval.

The CA server needs to send a http-post request to the ```/trigger``` and must send further payload as part the post request.

The data are expected to be send in json format; the payload must be base64 encoded.

```bash
# Modify to match your setup
BASE64_PAYLOAD=`echo "Hello Payload" | base64`
ACME2CERTIFIER_URL="http://10.97.149.146"

# Invoke curl
curl -X POST -H "Content-Type: application/json" -d "{\"payload\":\"$BASE64_PAYLOAD\"}" "$ACME2CERTIFIER_URL/trigger"
```

The payload will be forwarded extracted from the post-request and forwarded to the ```ca_handler.trigger()``` method for further processing.

It is expected that ```ca_handler.trigger()``` returns the following values:

- An error-message (if there is any)
- The Certificate chain in pem-format
- The certificate in asn1 (binary) format - base64 encoded - (needed for later revocation)

In case a valid certificate will be returned,  acme2certifier will update the local database set the status of the order resource to "valid".
The correlation between certificate and certificate resource will be done by comparing the public keys of certificate and CSR (which should
already exist in the database)
