package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

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
	FileAccessUUID []byte
}


// The struct for each node of the file's linked list
type FileNode struct {
	TextUUID         []byte
	NextNodeUUID     []byte
}


// The struct that holds the uuids of the accessors 
type FileAccess struct {
	//stores everyone we authorize (our part of the tree)
	AuthorizedUsers    map[string]byte
  }

//encrypted with RSA
type AuthorizedUserIntermediate struct {
	FileInterKey     []byte
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
	var publicKey userlib.PKEEncKey
	var privateKey userlib.PKEDecKey
	var signatureKey userlib.DSSignKey
	var verifyKey userlib.DSVerifyKey

	// Error checking for void username
	if (len(username) == 0) {
		return nil, errors.New("Cannot create a new user without an username")
	}

	// Generating PKE keys
	publicKey, privateKey, _ = userlib.PKEKeyGen()
	// Generating RSA keys
	signatureKey, verifyKey, _ = userlib.DSKeyGen()

	// Storing (username, verifyKey) in KeyStore
	userlib.KeystoreSet(username, verifyKey)

	// Generate macKey, encKey, and nameKey
	macKey, encKey, nameKey, err := GenerateKeys(username, password) 

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
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
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
	Helper methods
*/

// Helper to create macKey, encKey, nameKey
func GenerateKeys(username string, password string) (macKey []byte, encKey []byte, nameKey []byte, err error) {
	
	// Create generatedKey = Argon2Key(H(password), salt=H(username), length=16)
	usernameHash := userlib.Hash([]byte(username))
	passwordHash := userlib.Hash([]byte(password))
	generatedKey := userlib.Argon2Key(passwordHash, usernameHash, 16)

	// Use generated_key as a base key in HashKDF to regenerate pseudorandom children keys
	userKey, err := userlib.HashKDF(generatedKey, []byte("gen-key"))

	// Error checking if userlib.HashKDF fails
	if err != nil {
		return nil, nil, nil, errors.New("Cannot generate children keys from generatedKey")
	}

	// Set children keys
	macKey = userKey[0:16]
	encKey = userKey[16:32]
	nameKey = userKey[32:48]

	return macKey, encKey, nameKey, nil
}