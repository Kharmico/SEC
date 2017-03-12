# SEC

1ST PHASE
-----------------------------------------------------------------------------------------
Sistemas de Elevada Confiabilidade

KStore will save each user's Private Key
Map each entry user with a hash

Boot server: -KStore
Use AES/ECB/NoPadding as Cipher Mode

Load user's file from memory (not safe but they don't care for now)

Server has 2 files: -1 KeyStore for each its own private key
                    -1 txt file(eg) ciphered with each user's Public key, domain, username, password

Each user has its own KeyStore

Server KeyStore:
ks pass:a26tUfrGg4e4LHX
keytool -genkey -alias privateServerKey -keyalg RSA -keystore KeyStore.jks -keysize 2048


-----------------------------------------------------------------------------------------
                 
