Sure, here's a flowchart illustrating the communication between Alice, Bob, and the Bank, with Alice using a certificate from the Bank to verify her public key:

```
+-------------------+           +-------------------+                +-----------------+
|       Alice       |           |      Bank         |                |       Bob       |
+-------------------+           +-------------------+                +-----------------+
        |                           |        |                            |
        | Compose message           |        | Verify Alice's identity      |
        | Encrypt + Sign message    |        | Generate certificate         |
        | with private key         |        | with private key           |
        |                           |        |                           |
        | Obtain certificate        |        | Sign certificate           |
        | from Bank                 |        |                            |
        |                           |        | Send certificate + message |
        |                           |        | to Bob                     |
        |                           |        |                           |
+-------------------+           +-------------------+                +-----------------+
        |                           |        |                            |
        | Send message + certificate|        | Verify certificate          |
        | to Bob                     |        | with Bank's public key     |
        |                           |        |                            |
        |                           |        | Verify Alice's signature   |
        |                           |        | with Alice's public key    |
        |                           |        |                            |
+-------------------+           +-------------------+                +-----------------+
        |                           |        |                            |
        | Bob decrypts message     |        | If all validations pass:   |
        | with Alice's public key   |        | Trust message and act       |
        |                           |        | accordingly               |
        |                           |        | Else:                       |
        |                           |        | Reject message and         |
        |                           |        | investigate                |
        |                           |        |                            |
+-------------------+           +-------------------+                +-----------------+

**Note:** This is a simplified flowchart and may not represent all possible scenarios.
```

This flowchart assumes the following:

* Alice has a private/public key pair.
* Bob trusts the Bank as a certificate authority.
* The Bank has a verification process to confirm Alice's identity before issuing a certificate.
* Bob has access to the Bank's public key to verify the certificate.

I hope this helps!