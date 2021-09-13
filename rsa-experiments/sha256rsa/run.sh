# PKCS#1,
#
openssl genrsa -out key.pem 2048
openssl rsa -in key.pem -outform PEM -pubout -out public.pem

# Convert private Key to PKCS#8 format (so Java can read it)
openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt


# PCS#8,
# see https://blog.jonm.dev/posts/rsa-public-key-cryptography-in-java/
openssl genpkey -out rsakey.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048
openssl rsa -in rsakey.pem -pubout -outform DER -out rsakey_pub.der


javac -source 1.8 -target 1.8  SHA256RSA.java
java -cp . SHA256RSA 
