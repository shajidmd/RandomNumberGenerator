// PCSPRNG = Penta's crytographically secure pseudo-random number generator

package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/sha3"
	"hash/fnv"
	"math/big"
	"strconv"
	"time"
	// "github.com/codahale/blake2"
)

// The function GenerateRandomBytes returns securely generated random bytes and It will return an error if the system's secure random number generator fails to function correctly, in which case the caller should not continue.
func GenerateRandomBytes(nSize int) ([]byte, error) {
	randomBytes := make([]byte, nSize)
	_, err := rand.Read(randomBytes)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}

// The function GenerateRandomString returns a URL-safe, base64 encoded securely generated random string. It will return an error if the system's secure random number generator fails to function correctly, in which case the caller should not continue.
func GenerateRandomString(size int) (string, error) {
	randomString, err := GenerateRandomBytes(size)
	return base64.URLEncoding.EncodeToString(randomString), err
}

func MakeRange(min, max int) []int {
	a := make([]int, max-min+1)
	for i := range a {
		a[i] = min + i
	}
	return a
}

func integerHash(s string) uint64 {
	intHash := fnv.New64a()
	intHash.Write([]byte(s))
	return intHash.Sum64()
}

func PCSPRNG(sizeOfArray int) uint64 {

	// Get a random number from CryptoRand INT using the time.now() method as the maximun mumber
	var randomInteger *big.Int
	var err error
	maxIntFromCurrentTime := *big.NewInt(int64(time.Now().Nanosecond())) // To increase entropy take the time as max
	randomInteger, err = rand.Int(rand.Reader, &maxIntFromCurrentTime)
	randomInt := big.NewInt(randomInteger.Int64())
	randomIntAsString := randomInt.String()
	//fmt.Println(randomIntAsString)

	// Get a random string from CryptoRand Read and call this as the messageToken which is fed to a SHA3-Algorithm
	messageToken, err := GenerateRandomString(64)

	// fmt.Println("Message Token is : " + messageToken)

	// SHA3 Keccak secret key based ALGORITHM - USING a "sponge" construction and the Keccak permutation. For a detailed specification see http://keccak.noekeon.org/

	secretKey := []byte(randomIntAsString)
	buf := []byte(messageToken)
	// A MAC with 32 bytes of output has 256-bit security strength -- if you use at least a 32-byte-long key.
	initialHash := make([]byte, 64)
	hashConstruct := sha3.NewShake256()
	// Write the key into the hash.
	hashConstruct.Write(secretKey)
	// Now write the data.
	hashConstruct.Write(buf)
	// Read 32 bytes of output from the hash into h.
	hashConstruct.Read(initialHash)

	// fmt.Printf("%x\n", initialHash)

	// Blake2 Implementation Start
	// SHA3 NIST Finalist ALGORITHM - USING BLAKE 2 Which is a cryptographic hash functions based on Dan Bernstein's ChaCha stream cipher

	// initialHash := blake2.NewKeyedBlake2B([]byte(randomIntAsString))
	// initialHash.Write([]byte(messageToken))
	// finalHash := initialHash.Sum(nil)
	// Blake2 Implementation End

	//fmt.Printf("%X", finalHash)
	finalHash := initialHash
	has := base64.URLEncoding.EncodeToString(finalHash) // Base64 encoded the Final SHA3 HASH

	//fmt.Println("value is" + has)

	//String s := finalHash
	integerHash := integerHash(has)

	// Getting a randomNumber  with range the item size
	itemArrayLength := uint64(sizeOfArray)
	randomNumber := (integerHash % itemArrayLength)
	// fmt.Println(randomNumber)

	if err != nil {
		fmt.Println("Error Occured while generating random number")
		return 0
	}

	return randomNumber
}

func main() {
	// Example: Take 20 elements in an array say item1 to item20
	itemArray := make([]string, 0)
	for count := 1; count <= 20; count++ {
		itemArray = append(itemArray, "item"+strconv.Itoa(count))
	}
	sizeOfArray := len(itemArray)

	// Call random generator function to return random number
	randomNumber := PCSPRNG(sizeOfArray)

	//fmt.Println(len(a))

	// Use Random number to select element from the list
	fmt.Println("The random element from the list is : " + itemArray[randomNumber])

}
