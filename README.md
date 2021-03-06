# Penta Global's Crytographically Secure Pseudo-Random Number Generator using SHA-3(Keccak)

For any good Random Number Generator the Entropy should be high.

So the proposed random number generator using SHA-3 Keccak to generate a Hash. to generate the hash we use GoLangs NewShake256 method which creates a new SHAKE256 variable-output-length ShakeHash. Its generic security strength is 256 bits against all attacks if at least 64 bytes of its output are used and This method uses the below inputs :

1) SecretKey - The Secret Key is generated by getting a random number from GOLangs Crypto/Rand INT method while using the time.now() method as the maximum int limit. Here time.now() is used to increase the entropy.

2) The Buffer messageToken data  - The message to be hashed is generated by using Crypto/Rands Read method and later Base64 encoding it.

Point to be considered: 
* Reader is a global, shared instance of a cryptographically strong pseudo-random generator. On Linux, Reader uses getrandom(2) if available, /dev/urandom otherwise. On OpenBSD, Reader uses getentropy(2). On other Unix-like systems, Reader reads from /dev/urandom. On Windows systems, Reader uses the CryptGenRandom API.

Finally, the generated SHA-3 Keccak Hash is used to get an integer Hash using GoLangs hash/fnv's New64a method. New64a returns a new 64-bit FNV-1a hash.Hash. Its Sum method will lay the value out in big-endian byte order.

And then the randomNumber is calculated using the mod operator := (integerHash % itemArrayLength) where itemArrayLength is the size of the list.

USAGE:
Call the PCSPRNG(sizeOfArray) method where sizeOfArray is the size of the list, example shown in the main method.

* Instead of the default SHA-3 Keccak implementaion we can also use BLAKE-2 a SHA-3 variant and also a finalist SHA-3 cryptographic hash functions based on Dan Bernstein's ChaCha stream cipher. The implemenation is commented in the code.
