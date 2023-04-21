package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"
	"strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	Password string
	PrivateKey userlib.PKEDecKey
	SignatureKey userlib.DSSignKey
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}


// The struct for each file that informations on the starting 
// and ending nodes of the FileNode linked list
type File struct {
	Filename       string
	FirstNodeUUID  []byte
	LastNodeUUID   []byte
}


// The struct for each node of the file's linked list
type FileNode struct {
	NodeNum          int
	TextUUID         []byte
	NextNodeUUID     []byte
}


// The struct that holds the uuids of the accessors 
type FileAccess struct {
	//stores everyone we authorize (our part of the tree)
	AuthorizedUsers    []string
  }

//encrypted with RSA
type AuthorizedUserIntermediate struct {
	FileInterKey     []byte
	FileEncKey       []byte
	FileMacKey       []byte
  }


// The struct that holds the information about the file's data and its file keys
type AuthorizedUser struct {
	Owner           bool
	OwnerHash       []byte
	FileEncKey      []byte
	FileMacKey      []byte
	FileNameKey     []byte
  }


// The struct that stores the content of an AuthorizedUser struct.
type FileInvite struct {
	OwnerHash       []byte
	FileEncKey      []byte
	FileMacKey      []byte
	FileNameKey     []byte
	AuthorizedUserUUIDSignature  []byte
  }

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {

	// Variables initialization
	var userdata User
	var privateKey userlib.PKEDecKey
	var signatureKey userlib.DSSignKey
	var verifyKey userlib.DSVerifyKey

	// Error checking for void username
	if (len(username) == 0) {
		return nil, errors.New("Cannot create a new user without an username")
	}

	// Generating PKE keys
	publicKey, privateKey, _ := userlib.PKEKeyGen()
	// Generating RSA keys
	signatureKey, verifyKey, _ = userlib.DSKeyGen()

	// Storing (username, verifyKey) in KeyStore
	userlib.KeystoreSet(username + "verifyKey", verifyKey)
	// Storing (username, publicKey) in KeyStore
	userlib.KeystoreSet(username + "publicKey", publicKey)


	// Generate macKey, encKey, and nameKey
	macKey, encKey, err := GenerateKeys(username, password) 

	// Error checking if GenerateKeys fails
	if err != nil {
		return nil, errors.New("GenerateKeys fails")
	}

	// Create Hash(username)
	usernameHash := userlib.Hash([]byte(username))
	// Create UUID(Hash(username))
	userUUID, err := uuid.FromBytes((usernameHash[:16]))

	// Error checking if userUUID is already in DataStore
	if _, ok := userlib.DatastoreGet(userUUID); ok == true {
		return nil, errors.New("This username already exists in DataStore")
	}
	// Error checking if cannot create userUUID from usernameHash
	if err != nil {
		return nil, errors.New("Cannot create this userUUID")
	}
	
	// Create the User struct
	userdata = User{username, password, privateKey, signatureKey}
	// Change the User struct into a byte slice
	userdataByte, err := json.Marshal(userdata)
	// Error checking if json.Marshal fails
	if err != nil {
	return nil, errors.New("Cannot serialize the User struct")
	}

	// Create Enc(User struct)
	iv := userlib.RandomBytes(16)
	encryptedUser := userlib.SymEnc(encKey, iv, userdataByte)

	// Create HMAC(Enc(User struct)
	HMACEncryptedUser, err := userlib.HMACEval(macKey, encryptedUser)
	// Error checking if HMACEval fails
	if err != nil {
		return nil, errors.New("Cannot HMAC the encrypted User struct")
	}

	// Storing (userUUID, Enc(User struct) || HMAC(Enc(User struct)) in DataStore
	userlib.DatastoreSet(userUUID, append(encryptedUser, HMACEncryptedUser...))

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	
	// Recompute GenerateKeys
	macKey, encKey, err := GenerateKeys(username, password) 

	// Error checking if GenerateKeys fails
	if err != nil {
		return nil, errors.New("GenerateKeys fails")
	}

	// Create Hash(username)
	usernameHash := userlib.Hash([]byte(username))
	// Create UUID(Hash(username))
	userUUID, err := uuid.FromBytes((usernameHash[:16]))

	// Error checking if cannot create userUUID from usernameHash
	if err != nil {
		return nil, errors.New("Cannot create this userUUID")
	}

	// Decrypt the encryptedUser
	decryptedUser, err := userdata.ConfirmAuthencityHMAC(userUUID, macKey, encKey)
	// Error checking if data has been tampered
	if err != nil {
		return nil, errors.New("Data has been tampered with")
	}

	// Unmarshal the struct and recover user information
	json.Unmarshal(decryptedUser, &userdata)

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	
	// Generate macKey and encKey
	macKey, encKey, err := GenerateKeys(userdata.Username, userdata.Password) 
	// Error checking if GenerateKeys fails
	if err != nil {
		return errors.New("GenerateKeys fails")
	}

	publicKey, isFetched := userlib.KeystoreGet(userdata.Username + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if (!isFetched) {
		return errors.New("Cannot retrieve Public Key")
	}

	verifyKey, isFetched := userlib.KeystoreGet(userdata.Username + "verifyKey")
	// Error checking if cannot retrieve the KeyStore entry
	if (!isFetched) {
		return errors.New("Cannot retrieve Verify Key")
	}

	privateKey := userdata.PrivateKey
	signatureKey := userdata.SignatureKey
	
	// Check for AuthorizedUserIntermediate entry to determine whether the file already exists
	AuthorizedUserIntermediateEntry, err := userdata.AccessAuthorizedUserIntermediate(filename, publicKey)

	// If the error is not nil, then we are creating a new file and storing it
	if err != nil { 
		err = userdata.StoringNewFile(filename, content, encKey, macKey, publicKey, privateKey, signatureKey, verifyKey)
		if err != nil {
			return err
		}
	// If the error is nil, then we are accessing an existing file
	} else {
	
		// Retrieve the file
		fileEntryContent, _, fileEncKey, fileMacKey, fileNameKey, ownerHash, err := userdata.GetFile(filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
		if err != nil {
			return err
		}
		
		// Create a fileNode entry in DataStore based on the content we are overwriting the file with
		fileNodeKey, err := userdata.CreateFileNode(filename, fileNameKey, fileEncKey, fileMacKey, ownerHash, content, 1)
		if err != nil {
			return err
		}

		fileEntryContent.FirstNodeUUID = fileNodeKey
		fileEntryContent.LastNodeUUID = fileNodeKey

		// Change the File struct into a byte slice
		fileByte, err := json.Marshal(fileEntryContent)
		// Error checking if json.Marshal fails
		if err != nil {
		return errors.New("Cannot serialize the File struct")
		}

		// Re-encrypt the File struct, HMAC, and re-store in DataStore
		err = userdata.CreateFile(filename, fileNameKey, fileEncKey, fileMacKey, ownerHash, fileByte)
		if err != nil {
			return err
		}
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	
	publicKey, isFetched := userlib.KeystoreGet(userdata.Username + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if (!isFetched) {
		return nil, errors.New("Cannot retrieve Public Key")
	}

	verifyKey, isFetched := userlib.KeystoreGet(userdata.Username + "verifyKey")
	// Error checking if cannot retrieve the KeyStore entry
	if (!isFetched) {
		return nil, errors.New("Cannot retrieve Verify Key")
	}

	privateKey := userdata.PrivateKey
	
	// Check for AuthorizedUserIntermediate entry to determine whether the file already exists
	AuthorizedUserIntermediateEntry, err := userdata.AccessAuthorizedUserIntermediate(filename, publicKey)
	if err != nil {
		return nil, err
	}

	// Retrieve the file
	fileEntryContent, _, fileEncKey, fileMacKey, fileNameKey, _, err := userdata.GetFile(filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
	if err != nil {
		return nil, err
	}

	// Get the firstNode's key 
	firstNode := fileEntryContent.FirstNodeUUID

	content, nextNode, err := userdata.AccessFileNode(firstNode, fileNameKey, fileEncKey, fileMacKey)
	if err != nil {
		return nil, err
	}

	for (nextNode != nil) {
		text, nextNodeKey, err := userdata.AccessFileNode(nextNode, fileNameKey, fileEncKey, fileMacKey)
		if err != nil {
			return nil, err
		}
		nextNode = nextNodeKey
		content = append(content, text...)
	}

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}

/*
	HELPER METHODS
*/

// Helper to create macKey, encKey, nameKey
func GenerateKeys(username string, password string) (macKey []byte, encKey []byte, err error) {
	
	// Create generatedKey = Argon2Key(H(password), salt=H(username), length=16)
	usernameHash := userlib.Hash([]byte(username))
	passwordHash := userlib.Hash([]byte(password))
	generatedKey := userlib.Argon2Key(passwordHash, usernameHash, 16)

	// Use generated_key as a base key in HashKDF to regenerate pseudorandom children keys
	userKey, err := userlib.HashKDF(generatedKey, []byte("gen-key"))

	// Error checking if userlib.HashKDF fails
	if err != nil {
		return nil, nil, errors.New("Cannot generate children keys from generatedKey")
	}

	// Set children keys
	macKey = userKey[0:16]
	encKey = userKey[16:32]

	return macKey, encKey, nil
}

// Helper to confirm authenticity (data has not been tampered with) 
func (userdata *User) ConfirmAuthencityHMAC(entryKey userlib.UUID, macKey []byte, encKey []byte) (content []byte, err error) {

	// Fetching the DataStore entry
	dataStoreEntry, isFetched := userlib.DatastoreGet(entryKey)
	// Error checking if cannot retrieve the DataStore entry
	if (!isFetched) {
		return nil, errors.New("Cannot retrieve DataStore entry")
	}

	// Retrieve Enc(struct)
	encryptedStruct := dataStoreEntry[:len(dataStoreEntry) - 64]

	// Retrieve HMAC(Enc(struct))
	HMACEncryptedStruct := dataStoreEntry[len(dataStoreEntry) - 64:]

	// Create HMAC(Enc(struct) with the regenerated macKey
	newHMACEncryptedStruct, err := userlib.HMACEval(macKey, encryptedStruct)
	// Error checking if HMACEval fails
	if err != nil {
		return nil, errors.New("Cannot HMAC the encrypted struct")
	}

	// Confirm authenticity using HMACEqual()
	if (!userlib.HMACEqual(HMACEncryptedStruct, newHMACEncryptedStruct)) {
		return nil, errors.New("Data has been modified")
	}

	// Decrypt the encryptedStruct
	decryptedStruct := userlib.SymDec(encKey, encryptedStruct)

	return decryptedStruct, nil
}

// Helper function to check and decrypt the retrieved AuthorizedUserIntermediate
func (userdata *User) ConfirmAuthencityIntermediate(entryValue []byte, privateKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey) (content []byte, err error) {
	
	// Retrieve RSA(key = RSA public key, value = AuthorizedUserIntermediate struct)
	encryptedStruct := entryValue[:len(entryValue) - 256]

	// Retrieve RSA_SIG(msg = RSA(AuthorizedUserIntermediate struct), key = RSA Signature key)
	signature := entryValue[len(entryValue) - 256:]

	// Use the RSA public key to verify the signature
	err = userlib.DSVerify(verifyKey, encryptedStruct, signature)
	if err != nil {
		return nil, errors.New("Cannot verify the signature of this AuthorizedUserIntermediate")
	}

	// Decrypt RSA(key = RSA public key, value = AuthorizedUserIntermediate struct)
	content, err = userlib.PKEDec(privateKey, encryptedStruct)
	if err != nil {
		return nil, errors.New("Cannot decrypy this AuthorizedUserIntermediate entry")
	}
	
	return content, nil
}

// Helper function to access the FileNode struct in DataStore
func (userdata *User) AccessFileNode(entryKey []byte, fileNameKey []byte, fileEncKey []byte, fileMacKey []byte) (content []byte, nextNode []byte, err error) {
	// key: HKDF(key = fileNameKey, value = H(filename) || ownerHash || H("fileNode[num]"))
	
	
	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[:16]))
	// Error checking if cannot create UUID from entryKey
	if err != nil {
		return nil, nil, errors.New("Cannot create FileNode's UUID")
	}

	// Decrypt the retrieved FileNode entry
	decryptedFileNode, err := userdata.ConfirmAuthencityHMAC(entryUUID, fileMacKey, fileEncKey)
	if err != nil {
		return nil, nil, err
	}

	// Unmarshal the struct and recover information
	var fileNode FileNode
	json.Unmarshal(decryptedFileNode, &fileNode)
	
	contentKey := fileNode.TextUUID
	nextNode = fileNode.NextNodeUUID

	// Create UUID(contentKey)
	contentUUID, err := uuid.FromBytes((contentKey[:16]))
	// Error checking if cannot create UUID from contentKey
	if err != nil {
		return nil, nil, errors.New("Cannot create FileNodeContent's UUID")
	}

	// Decrypt the FileNodeContent entry
	decryptedFileNodeContent, err := userdata.ConfirmAuthencityHMAC(contentUUID, fileMacKey, fileEncKey)
	if err != nil {
		return nil, nil, err
	}

	// Unmarshal the content 
	json.Unmarshal(decryptedFileNodeContent, &content)

	return content, nextNode, err
}
// Helper function to access the File struct in DataStore
func (userdata *User) AccessFile(filename string, ownerHash []byte, fileNameKey []byte) (entryUUID userlib.UUID, err error) {
	// key: HKDF(key = fileNameKey, value = H(filename) || ownerHash || H("file"))
	
	// H(filename) || ownerHash || H("file")
	fileHash := userlib.Hash([]byte(filename))
	fileStringHash := userlib.Hash([]byte("file"))
	combinedHash := append(fileHash, ownerHash...)
	combinedHash = append(combinedHash, fileStringHash...)

	entryKey, err := userlib.HashKDF(fileNameKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return uuid.New(), errors.New("Cannot create the File's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err = uuid.FromBytes((entryKey[:16]))
	// Error checking if cannot create UUID from entryKey
	if err != nil {
		return uuid.New(), errors.New("Cannot create File's UUID")
	}

	return entryUUID, nil


}
// Helper function to access the AuthorizedUser struct in DataStore
func (userdata *User) AccessAuthorizedUser(filename string, fileInterKey []byte) (entryUUID userlib.UUID, err error) {
	// key: HKDF(key = fileInterKey, value = H(filename) || H(username) || H("authUser"))

	// H(filename) || H(username) || H("authUser")
	fileHash := userlib.Hash([]byte(filename))
	userHash := userlib.Hash([]byte(userdata.Username))
	authUserHash := userlib.Hash([]byte("authUser"))
	combinedHash := append(fileHash, userHash...)
	combinedHash = append(combinedHash, authUserHash...)

	entryKey, err := userlib.HashKDF(fileInterKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return uuid.New(), errors.New("Cannot create the Authorized User's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err = uuid.FromBytes((entryKey[:16]))
	// Error checking if cannot create UUID from entryKey
	if err != nil {
		return uuid.New(), errors.New("Cannot create Authorized User's UUID")
	}

	return entryUUID, nil
}

// Helper function to access the AuthorizedUserIntermediate struct in DataStore
func (userdata *User) AccessAuthorizedUserIntermediate(filename string, publicKey userlib.PKEEncKey) (structData []byte, err error) {
	// key: RSA(key = your PUBLIC rsa key,
	//	 value = "H(filename) || H(username) || H("Intermediate"))"

	// H(filename) || H(username) || H("Intermediate")
	fileHash := userlib.Hash([]byte(filename))
	userHash := userlib.Hash([]byte(userdata.Username))
	intermediateHash := userlib.Hash([]byte("Intermediate"))
	combinedHash := append(fileHash, userHash...)
	combinedHash = append(combinedHash, intermediateHash...)
	combinedHash = userlib.Hash(combinedHash)

	authorizedUserIntermediateEntryKey, err := userlib.PKEEnc(publicKey, combinedHash)
	// Error checking if cannot generate PKEEnc
	if err != nil {
		return nil, errors.New("Cannot use RSA public key to encrypt a message")
	}
	// Create UUID(authorizedUserIntermediateEntryKey)
	authorizedUserIntermediateUUID, err := uuid.FromBytes((authorizedUserIntermediateEntryKey[:16]))
	// Error checking if cannot create UUID from usernameHash
	if err != nil {
		return nil, errors.New("Cannot create authorizedUserIntermediateUUID ")
	}

	authorizedUserIntermediateEntry, isFetched := userlib.DatastoreGet(authorizedUserIntermediateUUID)
	// Error checking if cannot retrieve the DataStore entry
	if (!isFetched) {
		return nil, errors.New("Cannot retrieve DataStore entry")
	}

	return authorizedUserIntermediateEntry, nil
}

// Helper function to create an AuthorizedUserIntermediate entry in DataStore
func (userdata *User) CreateAuthorizedUserIntermediate(filename string, publicKey userlib.PKEEncKey, fileInterKey []byte, signatureKey userlib.DSSignKey, authorizedUserIntermediate []byte) (err error) { 
	// key: RSA(key = your PUBLIC rsa key, value ="H(filename) || H(username) || H("Intermediate"))"
	// value: RSA(key = RSA public key, value = AuthorizedUserIntermediate struct) || RSA_SIG(msg = RSA(AuthorizedUserIntermediate struct), key = RSA Signature key)

	// H(filename) || H(username) || H("Intermediate")
	fileHash := userlib.Hash([]byte(filename))
	userHash := userlib.Hash([]byte(userdata.Username))
	intermediateHash := userlib.Hash([]byte("Intermediate"))
	combinedHash := append(fileHash, userHash...)
	combinedHash = append(combinedHash, intermediateHash...)
	combinedHash = userlib.Hash(combinedHash)

	entryKey, err := userlib.PKEEnc(publicKey, combinedHash)
	// Error checking if cannot generate PKEEnc
	if err != nil {
		return errors.New("Cannot use RSA public key to encrypt a message")
	}

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[:16]))
	// Error checking if cannot create UUID from entryKey
	if err != nil {
		return errors.New("Cannot create authorizedUserIntermediateUUID ")
	}
	
	// RSA(key = RSA public key, value = AuthorizedUserIntermediate struct)
	entryRSA, err := userlib.PKEEnc(publicKey, authorizedUserIntermediate)
	// Error checking if cannot create the entryRSA
	if err != nil {
		return errors.New("Cannot use RSA public key to encrypt the AuthorizedUserIntermediate entry")
	}

	// RSA_SIG(msg = RSA, key = RSA Signature key)
	entryRSASignature, err := userlib.DSSign(signatureKey, entryRSA)
	// Error checking if cannot create the RSA Signature
	if err != nil {
		return errors.New("Cannot create the RSA Signature")
	}

	// RSA(key = RSA public key, value = fileInterKey) 
	// || RSA_SIG(msg = RSA, key = RSA Signature key)
	entryValue := append(entryRSA, entryRSASignature...)

	// Storing (key, value) in DataStore
	userlib.DatastoreSet(entryUUID, entryValue)

	return nil
}

// Helper function to create an AuthorizedUser entry in DataStore
func (userdata *User) CreateAuthorizedUser(filename string,  fileInterKey []byte, fileEncKey []byte, 
	fileMacKey []byte, authorizedUser []byte) (err error) { 

	// key: HKDF(key = fileInterKey, value = H(filename) || H(username) || H("authUser"))
 	// value: Enc(key = fileEncKey, value = AuthorizedUser struct) || 
	// HMAC(Enc(key = fileMacKey, value = AuthorizedUser struct))

	// H(filename) || H(username) || H("authUser")
	fileHash := userlib.Hash([]byte(filename))
	userHash := userlib.Hash([]byte(userdata.Username))
	authUserHash := userlib.Hash([]byte("authUser"))
	combinedHash := append(fileHash, userHash...)
	combinedHash = append(combinedHash, authUserHash...)

	entryKey, err := userlib.HashKDF(fileInterKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return errors.New("Cannot create the Authorized User's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[:16]))
	// Error checking if cannot create userUUID from entryKey
	if err != nil {
		return errors.New("Cannot create Authorized User's UUID")
	}

	// Enc(key = fileEncKey, value = AuthorizedUser struct)
	iv := userlib.RandomBytes(16)
	encryptedAuthorizedUser := userlib.SymEnc(fileEncKey, iv, authorizedUser)

	// HMAC(Enc(key = fileMacKey, value = AuthorizedUser struct))
	HMACEncryptedAuthorizedUser, err := userlib.HMACEval(fileMacKey, encryptedAuthorizedUser)
	// Error checking if HMACEval fails
	if err != nil {
		return errors.New("Cannot HMAC the encrypted struct")
	}

	entryValue := append(encryptedAuthorizedUser, HMACEncryptedAuthorizedUser...)

	// Storing (key, value) in DataStore
	userlib.DatastoreSet(entryUUID, entryValue)

	return nil
}

// Helper function to create a FileAccess entry in DataStore
func (userdata *User) CreateFileAccess(filename string, 
	fileInterKey []byte, fileEncKey []byte, fileMacKey []byte, fileAccess []byte) (err error) { 

	
	// key: HKDF(key = fileInterKey, value = H(filename) || H(username) || H("fileAccess"))
	// value: Enc(key = fileEncKey, value = FileAccess struct) 
	// || HMAC(Enc(key = fileMacKey, value = FileAccess struct))

	// H(filename) || H(username) || H("fileAccess")
	fileHash := userlib.Hash([]byte(filename))
	userHash := userlib.Hash([]byte(userdata.Username))
	fileAccessHash := userlib.Hash([]byte("fileAccess"))
	combinedHash := append(fileHash, userHash...)
	combinedHash = append(combinedHash, fileAccessHash...)

	entryKey, err := userlib.HashKDF(fileInterKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return errors.New("Cannot create the File Access's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[:16]))
	// Error checking if cannot create userUUID from entryKey
	if err != nil {
		return errors.New("Cannot create File Access's UUID")
	}

	// Enc(key = fileEncKey, value = FileAccess struct)
	iv := userlib.RandomBytes(16)
	encryptedFileAccess := userlib.SymEnc(fileEncKey, iv, fileAccess)

	// HMAC(Enc(key = fileMacKey, value = FileAccess struct))
	HMACEncryptedFileAccess, err := userlib.HMACEval(fileMacKey, encryptedFileAccess)
	// Error checking if HMACEval fails
	if err != nil {
		return errors.New("Cannot HMAC the encrypted struct")
	}

	entryValue := append(encryptedFileAccess, HMACEncryptedFileAccess...)

	// Storing (key, value) in DataStore
	userlib.DatastoreSet(entryUUID, entryValue)

	return nil
}

// Helper function to create a File entry in DataStore
func (userdata *User) CreateFile(filename string, fileNameKey []byte, 
	fileEncKey []byte, fileMacKey []byte, ownerHash []byte, file []byte) (err error) { 

	
	// key: HKDF(key = fileNameKey, value = H(filename) || ownerHash || H("file"))
	// value: Enc(key = fileEncKey, value = File struct) 
	// || HMAC(Enc(key = fileMacKey, value = File struct))

	// H(filename) || ownerHash || H("file")
	fileHash := userlib.Hash([]byte(filename))
	fileStringHash := userlib.Hash([]byte("file"))
	combinedHash := append(fileHash, ownerHash...)
	combinedHash = append(combinedHash, fileStringHash...)

	entryKey, err := userlib.HashKDF(fileNameKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return errors.New("Cannot create the File's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[:16]))
	// Error checking if cannot create userUUID from entryKey
	if err != nil {
		return errors.New("Cannot create File's UUID")
	}

	// Enc(key = fileEncKey, value = File struct)
	iv := userlib.RandomBytes(16)
	encryptedFile := userlib.SymEnc(fileEncKey, iv, file)

	// HMAC(Enc(key = fileMacKey, value = File struct))
	HMACEncryptedFile, err := userlib.HMACEval(fileMacKey, encryptedFile)
	// Error checking if HMACEval fails
	if err != nil {
		return errors.New("Cannot HMAC the encrypted struct")
	}

	entryValue := append(encryptedFile, HMACEncryptedFile...)

	// Storing (key, value) in DataStore
	userlib.DatastoreSet(entryUUID, entryValue)

	return nil
}

// Helper function to create a FileNode entry in DataStore
func (userdata *User) CreateFileNode(filename string, fileNameKey []byte, fileEncKey []byte, 
	fileMacKey []byte, ownerHash []byte, content []byte, nodeNum int) (fileNodeEntryKey []byte, err error) { 

	// Create the content entry in DataStore to point the TextUUID field of the struct to

	// key: HKDF(key = fileNameKey, value = H(filename) || OwnerHash || H("fileNodeContent[num]"))
	// value: Enc(key = fileEncKey, value = contents of file) || HMAC(Enc(key = fileMacKey, value = contents of file))
	nodeNumString := strconv.Itoa(nodeNum)
	// H(filename) || OwnerHash || H("fileNodeContent[num]")
	fileHash := userlib.Hash([]byte(filename))
	fileNodeContentNum := userlib.Hash([]byte("fileNodeContent"+nodeNumString))
	combinedHash := append(fileHash, ownerHash...)
	combinedHash = append(combinedHash, fileNodeContentNum...)

	contentEntryKey, err := userlib.HashKDF(fileNameKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return nil, errors.New("Cannot create the content's entry key")
	}

	// Create UUID(contentEntryKey)
	contentEntryUUID, err := uuid.FromBytes((contentEntryKey[:16]))
	// Error checking if cannot create userUUID from entryKey
	if err != nil {
		return nil, errors.New("Cannot create contentEntryUUID")
	}

	// Enc(key = file_enc_key, value = contents of file) 
	iv := userlib.RandomBytes(16)
	encryptedContent := userlib.SymEnc(fileEncKey, iv, content)

	// HMAC(Enc(key = file_mac_key, value = contents of file))
	HMACEncryptedContent, err := userlib.HMACEval(fileMacKey, encryptedContent)
	// Error checking if HMACEval fails
	if err != nil {
		return nil, errors.New("Cannot HMAC the encrypted content")
	}

	contentEntryValue := append(encryptedContent, HMACEncryptedContent...)

	// Storing (key, value) in DataStore
	userlib.DatastoreSet(contentEntryUUID, contentEntryValue)
	

	// Create the FileNode entry in DataStore
	
	
	// key: HKDF(key = fileNameKey, value = H(filename) || OwnerHash || H("fileNode[num]"))
	// value: Enc(key = fileEncKey, value = FileNode struct) || HMAC(Enc(key = fileMacKey, value =FileNode struct))

	// H(filename) || OwnerHash || H("fileNode[num]")
	fileNodeNum := userlib.Hash([]byte("fileNode"+nodeNumString))
	newCombinedHash := append(fileHash, ownerHash...)
	newCombinedHash = append(newCombinedHash, fileNodeNum...)

	entryKey, err := userlib.HashKDF(fileNameKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return nil, errors.New("Cannot create the File Node's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[:16]))
	// Error checking if cannot create userUUID from entryKey
	if err != nil {
		return nil, errors.New("Cannot create File Node's UUID")
	}

	// Create the FileNode struct
	fileNodeStruct := FileNode{nodeNum, contentEntryKey, nil}
	// Change the FileNode struct into a byte slice
	fileNodeByte, err := json.Marshal(fileNodeStruct)
	// Error checking if json.Marshal fails
	if err != nil {
	return nil, errors.New("Cannot serialize the FileNode struct")
	}

	// Enc(key = fileEncKey, value = FileNode struct)
	iv = userlib.RandomBytes(16)
	encryptedFileNode := userlib.SymEnc(fileEncKey, iv, fileNodeByte)

	// HMAC(Enc(key = fileMacKey, value = FileNode struct))
	HMACEncryptedFileNode, err := userlib.HMACEval(fileMacKey, encryptedFileNode)
	// Error checking if HMACEval fails
	if err != nil {
		return nil, errors.New("Cannot HMAC the encrypted struct")
	}

	entryValue := append(encryptedFileNode, HMACEncryptedFileNode...)

	// Storing (key, value) in DataStore
	userlib.DatastoreSet(entryUUID, entryValue)

	return entryKey, nil
}

// Helper function to retrieve the File struct after obtaining the AuthorizedUserIntermediate entry
func (userdata *User) GetFile(filename string, authorizedUserIntermediate []byte, 
	privateKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey) (fileContent File, 
		fileInterKey []byte, fileEncKey []byte, fileMacKey []byte, fileNameKey []byte, ownerHash []byte, err error) {
	var fileEntryContent File
	// Check integrity and decrypt the retrieved AuthorizedUserIntermediate entry 
	decryptedIntermediate, err := userdata.ConfirmAuthencityIntermediate(authorizedUserIntermediate, privateKey, verifyKey)
	if err != nil {
		return fileEntryContent, nil, nil, nil, nil, nil, err
	}

	// Unmarshal the struct and recover information
	var intermediateContent AuthorizedUserIntermediate
	json.Unmarshal(decryptedIntermediate, &intermediateContent)

	// Retrieve fileInterKey, fileEncKey, and fileMacKey
	fileInterKey = intermediateContent.FileInterKey
	fileEncKey = intermediateContent.FileEncKey
	fileMacKey = intermediateContent.FileMacKey

	// Access the AuthorizedUser entry in DataStore
	authorizedUserUUID, err := userdata.AccessAuthorizedUser(filename, fileInterKey)
	if err != nil {
		return fileEntryContent, nil, nil, nil, nil, nil, err
	}

	// Decrypt the retrieved AuthorizedUser entry
	decryptedAuthorizedUser, err := userdata.ConfirmAuthencityHMAC(authorizedUserUUID, fileMacKey, fileEncKey)
	if err != nil {
		return fileEntryContent, nil, nil, nil, nil, nil, err
	}

	// Unmarshal the struct and recover information
	var authorizedUserContent AuthorizedUser
	json.Unmarshal(decryptedAuthorizedUser, &authorizedUserContent)

	// Retrieve ownerHash and fileNameKey
	ownerHash = authorizedUserContent.OwnerHash
	fileNameKey = authorizedUserContent.FileNameKey

	// Access the File entry in DataStore
	fileUUID, err := userdata.AccessFile(filename, ownerHash, fileNameKey)
	if err != nil {
		return fileEntryContent, nil, nil, nil, nil, nil, err
	}

	// Decrypt the retrieved File entry
	decryptedFile, err := userdata.ConfirmAuthencityHMAC(fileUUID, fileMacKey, fileEncKey)
	if err != nil {
		return fileEntryContent, nil, nil, nil, nil, nil, err
	}
	// Unmarshal the struct and recover information
	json.Unmarshal(decryptedFile, &fileEntryContent)

	return fileEntryContent, fileInterKey, fileEncKey, fileMacKey, fileNameKey, ownerHash, nil
}


// Helper function to create a file_key for encryption and decryption
func GenerateFileKeys() (fileEncKey []byte, fileMacKey []byte, fileNameKey []byte, fileInterKey []byte, err error) {
	fileKey := userlib.RandomBytes(64)
	fileEncKey = fileKey[0:16]
	fileMacKey = fileKey[16:32]
	fileNameKey = fileKey[32:48]
	fileInterKey = fileKey[48:64]

	return fileEncKey, fileMacKey, fileNameKey, fileInterKey, nil
}

// Helper function to store a new file (with userdata as the owner)
func (userdata *User) StoringNewFile(filename string, content []byte, encKey []byte, macKey []byte, publicKey userlib.PKEEncKey,
	privateKey userlib.PKEDecKey, signatureKey userlib.DSSignKey, verifyKey userlib.DSVerifyKey) (err error) {

	// Generate fileKey parts
	fileEncKey, fileMacKey, fileNameKey, fileInterKey, err := GenerateFileKeys()
	// Error checking if GenerateFileKeys fails
	if err != nil {
		return errors.New("GenerateFileKeys fails")
	}

	// Create an AuthorizedUserIntermediate entry in DataStore

	// Create the AuthorizedUserIntermediate struct
	authorizedUserIntermediateStruct := AuthorizedUserIntermediate{fileInterKey, fileEncKey, fileMacKey}
	// Change the AuthorizedUser struct into a byte slice
	authorizedUserIntermediateByte, err := json.Marshal(authorizedUserIntermediateStruct)
	// Error checking if json.Marshal fails
	if err != nil {
	return errors.New("Cannot serialize the AuthorizedUser struct")
	}

	err = userdata.CreateAuthorizedUserIntermediate(filename, publicKey, fileInterKey, signatureKey, authorizedUserIntermediateByte)
	// Error checking if cannot create an AuthorizedUserIntermediate entry in DataStore
	if err != nil {
		return err
	}

	// Create an AuthorizedUser entry in DataStore
	// Create the OwnerHash = Enc(value = Owner's username, key = enc_key, iv=random)
	iv := userlib.RandomBytes(16)
	ownerHash := userlib.SymEnc(encKey, iv, []byte(userdata.Username))

	// Create the AuthorizedUser struct
	authorizedUserStruct := AuthorizedUser{true, ownerHash, fileEncKey, fileMacKey, fileNameKey}
	// Change the AuthorizedUser struct into a byte slice
	authorizedUserByte, err := json.Marshal(authorizedUserStruct)
	// Error checking if json.Marshal fails
	if err != nil {
	return errors.New("Cannot serialize the AuthorizedUser struct")
	}

	err = userdata.CreateAuthorizedUser(filename, fileInterKey, fileEncKey, fileMacKey, authorizedUserByte)
	// Error checking if cannot create an AuthorizedUser entry in DataStore
	if err != nil {
		return err
	}

	// Create a FileAccess entry in DataStore
	// Create the FileAccess struct
	authorizedUsers := make([]string, 1)
	authorizedUsers[0] = userdata.Username
	
	fileAccessStruct:= FileAccess{authorizedUsers}
	// Change the File Access struct into a byte slice
	fileAccessByte, err := json.Marshal(fileAccessStruct)
	// Error checking if json.Marshal fails
	if err != nil {
	return errors.New("Cannot serialize the FileAccess struct")
	}

	err = userdata.CreateFileAccess(filename, fileInterKey, fileEncKey, fileMacKey, fileAccessByte)
	if err != nil {
		return err
	}

	// Create a FileNode entry in DataStore
	nodeNum := 1
	fileNodeEntry, err := userdata.CreateFileNode(filename, fileNameKey, fileEncKey, fileMacKey, ownerHash, content, nodeNum)
	if err != nil {
		return err
	}

	// Create a File entry in DataStore
	
	// Create the File struct
	fileStruct := File{filename, fileNodeEntry, fileNodeEntry}
	// Change the AuthorizedUser struct into a byte slice
	fileByte, err := json.Marshal(fileStruct)
	// Error checking if json.Marshal fails
	if err != nil {
	return errors.New("Cannot serialize the File struct")
	}

	err = userdata.CreateFile(filename, fileNameKey, fileEncKey, fileMacKey, ownerHash, fileByte)
	if err != nil {
		return  err
	}

	return nil
}