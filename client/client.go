package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/hex"
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

type MailBox struct {
	InterUUID    []byte
}

type AuthorizedTo struct {
	AuthoriedToList []SharedFrom // filename: username
}

type SharedFrom struct {
	Username  string
	Filename  []byte
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username     string
	Password     string
	PrivateKey   userlib.PKEDecKey
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
	FirstNodeUUID []byte
	LastNodeUUID  []byte
}

// The struct for each node of the file's linked list
type FileNode struct {
	NodeNum      int
	TextUUID     []byte
	NextNodeUUID []byte
}

// The struct that holds the uuids of the accessors
type FileAccess struct {
	//stores everyone we authorize (our part of the tree)
	AuthorizedUsers []string
}

type InterContent struct {
	FileEncKey   []byte
	FileMacKey   []byte
}
// encrypted with RSA
type AuthorizedUserIntermediate struct {
	FEnc         []byte
	FMac         []byte
	FInter       []byte
	OH           []byte
}

// The struct that holds the information about the file's data and its file keys
type AuthorizedUser struct {
	OwnerFileAlias []byte
	Owner          bool
	OwnerHash      []byte
	FileEncKey     []byte
	FileMacKey     []byte
	FileNameKey    []byte
	FileInterKey   []byte
	OwnerPublicKey userlib.PKEEncKey
}

// The struct that stores the content of an AuthorizedUser struct.
type FileInvite struct {
	Sender     []byte
	FileEncKey []byte
	FileMacKey []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {

	// Variables initialization
	var userdata User
	var privateKey userlib.PKEDecKey
	var signatureKey userlib.DSSignKey
	var verifyKey userlib.DSVerifyKey

	// Error checking for void username
	if len(username) == 0 {
		return nil, errors.New("Cannot create a new user without an username")
	}

	// Generating PKE keys
	publicKey, privateKey, _ := userlib.PKEKeyGen()
	// Generating RSA keys
	signatureKey, verifyKey, _ = userlib.DSKeyGen()

	// Storing (username, verifyKey) in KeyStore
	userlib.KeystoreSet(username+"verifyKey", verifyKey)

	// Storing (username, publicKey) in KeyStore
	userlib.KeystoreSet(username+"publicKey", publicKey)

	// Generate macKey, encKey, and nameKey
	macKey, encKey, _, err := GenerateKeys(username, password)

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

	// Create an empty AuthorizedTo struct :)
	sharedFromList := make([]SharedFrom, 1)
	sharedFrom := SharedFrom{userdata.Username, nil}
	sharedFromList[0] = sharedFrom
	authorizedToStruct := AuthorizedTo{sharedFromList}

	authorizedToByte, err := json.Marshal(authorizedToStruct)
	if err != nil {
		return nil, err
	}

	err = userdata.CreateAuthorizedTo(username, password, authorizedToByte)
	if err != nil {
		return nil, err
	}
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	// Recompute GenerateKeys
	macKey, encKey, _, err := GenerateKeys(username, password)

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
	decryptedUser, err := userdata.ConfirmAuthenticityHMAC(userUUID, macKey, encKey)
	// Error checking if data has been tampered
	if err != nil {
		return nil, errors.New("Data has been tampered with")
	}

	// Unmarshal the struct and recover user information
	json.Unmarshal(decryptedUser, &userdata)

	authorizedToUUID, err := userdata.AccessAuthorizedTo(username)
	if err != nil {
		return nil, errors.New("Cannot retrieve authorizedToUUID")
	}

	// Decrypt the encryptedUser
	_, err = userdata.ConfirmAuthenticityHMAC(authorizedToUUID, macKey, encKey)
	// Error checking if data has been tampered
	if err != nil {
		return nil, errors.New("Data has been tampered with")
	}

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(fn string, content []byte) (err error) {

	// Generate macKey and encKey
	macKey, encKey, nameKey, err := GenerateKeys(userdata.Username, userdata.Password)
	// Error checking if GenerateKeys fails
	if err != nil {
		return errors.New("GenerateKeys fails")
	}

	publicKey, isFetched := userlib.KeystoreGet(userdata.Username + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return errors.New("Cannot retrieve Public Key")
	}
	//get alias
	filename, err := userdata.GetFileAlias(fn, nameKey)
	if err != nil {
		return err
	}

	verifyKey, isFetched := userlib.KeystoreGet(userdata.Username + "verifyKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return errors.New("Cannot retrieve Verify Key")
	}

	privateKey := userdata.PrivateKey
	signatureKey := userdata.SignatureKey

	// Check for AuthorizedUserIntermediate entry to determine whether the file already exists
	_, AuthorizedUserIntermediateEntry, err := AccessAuthorizedUserIntermediate(filename, nameKey, userdata.Username, publicKey)

	// If the error is not nil, then we are creating a new file and storing it
	if err != nil {
		err = userdata.StoringNewFile(filename, content, encKey, macKey, nameKey, publicKey, privateKey, signatureKey, verifyKey)
		if err != nil {
			return err
		}
		userlib.DebugMsg("storing new file; filename = %s, owner = %s, owner pk = %s", filename, userdata.Username, publicKey)

		// If the error is nil, then we are accessing an existing file
	} else {

		// Retrieve the file
		fileEntryContent, _, fileEncKey, fileMacKey, fileNameKey, ownerHash, originalFileName, err := userdata.GetFile(filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
		if err != nil {
			return err
		}

		// Create a fileNode entry in DataStore based on the content we are overwriting the file with
		fileNodeKey, err := userdata.CreateNewFileNode(originalFileName, fileNameKey, fileEncKey, fileMacKey, ownerHash, content, 1)
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
		err = userdata.CreateFile(originalFileName, fileNameKey, fileEncKey, fileMacKey, ownerHash, fileByte)
		if err != nil {
			return err
		}
	}
	return nil
}

func (userdata *User) AppendToFile(fn string, content []byte) error {
	// Generate macKey and encKey
	_, _, nameKey, err := GenerateKeys(userdata.Username, userdata.Password)

	// Error checking if GenerateKeys fails
	if err != nil {
		return errors.New("GenerateKeys fails")
	}

	publicKey, isFetched := userlib.KeystoreGet(userdata.Username + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return errors.New("Cannot retrieve Public Key")
	}

	verifyKey, isFetched := userlib.KeystoreGet(userdata.Username + "verifyKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return errors.New("Cannot retrieve Verify Key")
	}

	privateKey := userdata.PrivateKey
	filename, err := userdata.GetFileAlias(fn, nameKey)
	if err != nil {
		return err
	}

	// Check for AuthorizedUserIntermediate entry to determine whether the file already exists
	_, AuthorizedUserIntermediateEntry, err := AccessAuthorizedUserIntermediate(filename, nameKey, userdata.Username, publicKey)
	if err != nil {
		return err
	}

	// Retrieve the file
	fileEntryContent, _, fileEncKey, fileMacKey, fileNameKey, ownerHash, originalFileName, err := userdata.GetFile(filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
	if err != nil {
		return err
	}

	// Get the firstNode's key
	lastNodeKey := fileEntryContent.LastNodeUUID

	// Get the FileNode struct of lastNode
	lastNode, err := userdata.AccessFileNode(lastNodeKey, fileNameKey, fileEncKey, fileMacKey)
	if err != nil {
		return err
	}

	nodeNum := lastNode.NodeNum

	// Create a new FileNode entry in DataStore
	newNode, err := userdata.CreateNewFileNode(originalFileName, fileNameKey, fileEncKey, fileMacKey, ownerHash, content, nodeNum+1)
	if err != nil {
		return err
	}

	// Set lastNode's next to newNode
	lastNode.NextNodeUUID = newNode

	// Change the FileNode struct into a byte slice
	nodeByte, err := json.Marshal(lastNode)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the File struct")
	}

	// Re-encrypt the FileNode struct, HMAC, and re-store in DataStore
	err = userdata.CreateFileNode(originalFileName, fileNameKey, fileEncKey, fileMacKey, ownerHash, nodeNum, nodeByte)
	if err != nil {
		return err
	}

	// Change the file's last node to the new node
	fileEntryContent.LastNodeUUID = newNode
	// Change the File struct into a byte slice
	fileByte, err := json.Marshal(fileEntryContent)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the File struct")
	}
	// Re-encrypt the File struct, HMAC, and re-store in DataStore
	err = userdata.CreateFile(originalFileName, fileNameKey, fileEncKey, fileMacKey, ownerHash, fileByte)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(fn string) (content []byte, err error) {
	// Generate macKey and encKey
	_, _, nameKey, err := GenerateKeys(userdata.Username, userdata.Password)

	// Error checking if GenerateKeys fails
	if err != nil {
		return nil, errors.New("GenerateKeys fails")
	}

	filename, err := userdata.GetFileAlias(fn, nameKey)
	if err != nil {
		return nil, err
	}

	publicKey, isFetched := userlib.KeystoreGet(userdata.Username + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return nil, errors.New("Cannot retrieve Public Key")
	}

	verifyKey, isFetched := userlib.KeystoreGet(userdata.Username + "verifyKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return nil, errors.New("Cannot retrieve Verify Key")
	}

	privateKey := userdata.PrivateKey

	// Check for AuthorizedUserIntermediate entry to determine whether the file already exists
	_, AuthorizedUserIntermediateEntry, err := AccessAuthorizedUserIntermediate(filename, nameKey, userdata.Username, publicKey)
	if err != nil {
		return nil, err
	}
	// Check integrity and decrypt the retrieved AuthorizedUserIntermediate entry
	_, err = userdata.ConfirmAuthenticityIntermediate(filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
	if err != nil {
		return nil, err
	}

	// Retrieve the file
	fileEntryContent, _, fileEncKey, fileMacKey, fileNameKey, _, _, err := userdata.GetFile(filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
	if err != nil {
		return nil, err
	}

	// Get the firstNode's key
	firstNode := fileEntryContent.FirstNodeUUID

	content, nextNode, _, _, err := userdata.AccessFileNodeContent(firstNode, fileNameKey, fileEncKey, fileMacKey)
	if err != nil {
		return nil, err
	}

	for nextNode != nil {
		text, nextNodeKey, _, _, err := userdata.AccessFileNodeContent(nextNode, fileNameKey, fileEncKey, fileMacKey)
		if err != nil {
			return nil, err
		}
		nextNode = nextNodeKey
		content = append(content, text...)
	}

	return content, err
}

func (userdata *User) CreateInvitation(fn string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// Generate macKey and encKey
	_, _, nameKey, err := GenerateKeys(userdata.Username, userdata.Password)
	// Error checking if GenerateKeys fails
	if err != nil {
		return uuid.New(), errors.New("GenerateKeys fails")
	}

	filename, err := userdata.GetFileAlias(fn, nameKey)
	if err != nil {
		return uuid.New(), err
	}

	publicKey, isFetched := userlib.KeystoreGet(userdata.Username + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return uuid.New(), errors.New("Cannot retrieve Public Key")
	}

	verifyKey, isFetched := userlib.KeystoreGet(userdata.Username + "verifyKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return uuid.New(), errors.New("Cannot retrieve Verify Key")
	}

	privateKey := userdata.PrivateKey

	// Check for AuthorizedUserIntermediate entry to determine whether the file already exists
	_, AuthorizedUserIntermediateEntry, err := AccessAuthorizedUserIntermediate(filename, nameKey, userdata.Username, publicKey)
	if err != nil {
		return uuid.New(), err
	}

	// Retrieve the file
	_, _, _, _, _, _, _, err = userdata.GetFile(filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
	if err != nil {
		return uuid.New(), err
	}


	authorizedUserContent, senderAuthorizedUser, fileInterKey, err := userdata.GetAuthorizedUser(userdata.Username, filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
	if err != nil {
		return uuid.New(), err
	}

	fileEncKey := authorizedUserContent.FileEncKey
	fileNameKey := authorizedUserContent.FileNameKey
	fileMacKey := authorizedUserContent.FileMacKey
	ownerFileAlias := authorizedUserContent.OwnerFileAlias
	ownerHash := authorizedUserContent.OwnerHash

	
	// Find the recipient's publicKey
	recipientPublicKey, isFetched := userlib.KeystoreGet(recipientUsername + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return uuid.New(), errors.New("Cannot retrieve Public Key")
	}

	// Check for the recipient's AuthorizedUser entry to determine whether they already have access to the file
	authorizedUserUUID, _, err := AccessAuthorizedUser(ownerHash, recipientUsername, fileInterKey)
	if err != nil {
		return uuid.New(), err
	}

	_, isFetched = userlib.DatastoreGet(authorizedUserUUID)
	// Error checking if cannot retrieve the DataStore entry
	if isFetched {
		return uuid.New(), errors.New("The recipient already has access to the file")
	}

	// Create a new FileInvite struct
	fileInviteStruct := FileInvite{senderAuthorizedUser, fileEncKey, fileMacKey}
	// Change the FileInvite struct into a byte slice
	fileInviteByte, err := json.Marshal(fileInviteStruct)
	// Error checking if json.Marshal fails
	if err != nil {
		return uuid.New(), errors.New("Cannot serialize the FileAccess struct")
	}

	fileInviteUUID, err := CreateFileInvite(ownerFileAlias, userdata.Username, recipientPublicKey, fileNameKey, userdata.SignatureKey, fileInviteByte)
	if err != nil {
		return uuid.New(), err
	}

	// Access the sender's (our) file access struct
	fileAccessKey, err := userdata.AccessFileAccess(userdata.Username, ownerFileAlias, fileInterKey)
	if err != nil {
		return uuid.New(), err
	}

	// Decrypt the entry
	fileAccessValue, err := userdata.ConfirmAuthenticityHMAC(fileAccessKey, fileMacKey, fileEncKey)
	if err != nil {
		return uuid.New(), err
	}

	// Unmarshal the struct and recover information
	var fileAccess FileAccess
	json.Unmarshal(fileAccessValue, &fileAccess)

	// Add recipientUsername to our FileAccess struct’s list of authorized users
	fileAccess.AuthorizedUsers = append(fileAccess.AuthorizedUsers, recipientUsername)
	// Change the File struct into a byte slice
	fileAccessByte, err := json.Marshal(fileAccess)
	// Error checking if json.Marshal fails
	if err != nil {
		return uuid.New(), errors.New("Cannot serialize the File struct")
	}
	// Re-encrypt the File struct, HMAC, and re-store in DataStore
	err = userdata.CreateFileAccess(userdata.Username, ownerFileAlias, fileInterKey, fileEncKey, fileMacKey, fileAccessByte)
	if err != nil {
		return uuid.New(), err
	}

	return fileInviteUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, fn string) error {
	// Generate macKey and encKey
	macKey, encKey, nameKey, err := GenerateKeys(userdata.Username, userdata.Password)
	// Error checking if GenerateKeys fails
	if err != nil {
		return errors.New("GenerateKeys fails")
	}
	userlib.DebugMsg("This invitation has the uuid of %x", invitationPtr)
	filename, err := userdata.GetFileAlias(fn, nameKey)
	if err != nil {
		return err
	}

	publicKey, isFetched := userlib.KeystoreGet(userdata.Username + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return errors.New("Cannot retrieve Public Key")
	}

	signatureKey := userdata.SignatureKey

	// Fetching the FileInvite DataStore entry
	fileInviteEntry, isFetched := userlib.DatastoreGet(invitationPtr)
	// Error checking if cannot retrieve the DataStore entry
	if !isFetched {
		return errors.New("Cannot retrieve the FileInvite entry")
	}

	senderVerifyKey, isFetched := userlib.KeystoreGet(senderUsername + "verifyKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return errors.New("Cannot retrieve the sender's Verify Key")
	}

	// Retrieve RSA(key = RSA public key, value = AuthorizedUserIntermediate struct)
	rsaVal := fileInviteEntry[:len(fileInviteEntry)-256]

	// Retrieve RSA_SIG(msg = RSA(FileInvite struct), key = recipientPubKey)
	signature := fileInviteEntry[len(fileInviteEntry)-256:]

	// Use the RSA public key to verify the signature
	err = userlib.DSVerify(senderVerifyKey, rsaVal, signature)
	if err != nil {
		return errors.New("Cannot verify the signature of this FileInvite")
	}

	// Decrypt RSA(key = recipientPublicKey, value = FileInvite struct)
	decryptedFileInvite, err := userlib.PKEDec(userdata.PrivateKey, rsaVal)
	if err != nil {
		return errors.New("Cannot decrypt this FileInvite entry")
	}

	// Unmarshal the struct and recover information
	var fileInvite FileInvite
	json.Unmarshal(decryptedFileInvite, &fileInvite)

	// Retrieve fileInterKey, fileEncKey, and fileMacKey
	fileEncKey := fileInvite.FileEncKey
	fileMacKey := fileInvite.FileMacKey
	senderAuthorizedUser := fileInvite.Sender

	// Create UUID(senderAuthorizedUser)
	senderUUID, err := uuid.FromBytes(senderAuthorizedUser)
	// Error checking if cannot create UUID from entryKey
	if err != nil {
		return errors.New("Cannot create the sender's AuthorizedUser UUID")
	}

	// Decrypt the sender's AuthorizedUser entry
	decryptedSenderAuthorizedUser, err := userdata.ConfirmAuthenticityHMAC(senderUUID, fileMacKey, fileEncKey)
	if err != nil {
		return err
	}

	// Unmarshal the struct and recover information
	var senderAuthorizedUserContent AuthorizedUser
	json.Unmarshal(decryptedSenderAuthorizedUser, &senderAuthorizedUserContent)

	ownerHash := senderAuthorizedUserContent.OwnerHash
	fileNameKey := senderAuthorizedUserContent.FileNameKey
	fileInterKey := senderAuthorizedUserContent.FileInterKey
	ownerFileAlias := senderAuthorizedUserContent.OwnerFileAlias
	ownerPublicKey := senderAuthorizedUserContent.OwnerPublicKey

	// Create the AuthorizedUserIntermediate struct
	authorizedUserIntermediateStruct := AuthorizedUserIntermediate{fileEncKey, fileMacKey, fileInterKey, ownerHash}
	// Change the AuthorizedUser struct into a byte slice
	authorizedUserIntermediateByte, err := json.Marshal(authorizedUserIntermediateStruct)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the AuthorizedUser struct")
	}

	err = userdata.CreateAuthorizedUserIntermediate(userdata.Username, filename, nameKey, publicKey, fileInterKey, signatureKey, authorizedUserIntermediateByte)
	// Error checking if cannot create an AuthorizedUserIntermediate entry in DataStore
	if err != nil {
		return err
	}

	// Create the AuthorizedUser struct
	authorizedUserStruct := AuthorizedUser{ownerFileAlias, false, ownerHash, fileEncKey, fileMacKey, fileNameKey, fileInterKey, ownerPublicKey}
	// Change the AuthorizedUser struct into a byte slice
	authorizedUserByte, err := json.Marshal(authorizedUserStruct)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the AuthorizedUser struct")
	}

	err = userdata.CreateAuthorizedUser(userdata.Username, ownerHash, fileInterKey, fileEncKey, fileMacKey, authorizedUserByte)
	// Error checking if cannot create an AuthorizedUser entry in DataStore
	if err != nil {
		return err
	}

	// Create a FileAccess entry in DataStore
	// Create the FileAccess struct
	authorizedUsers := make([]string, 1)
	authorizedUsers[0] = userdata.Username

	fileAccessStruct := FileAccess{authorizedUsers}
	// Change the File Access struct into a byte slice
	fileAccessByte, err := json.Marshal(fileAccessStruct)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the FileAccess struct")
	}

	err = userdata.CreateFileAccess(userdata.Username, ownerFileAlias, fileInterKey, fileEncKey, fileMacKey, fileAccessByte)
	if err != nil {
		return err
	}

	// Create a MailBox entry in DataStore
	authorizedUserInterKey, _, err := AccessAuthorizedUserIntermediate(filename, nameKey, userdata.Username, publicKey)
	if err != nil {
		return err
	}

	mailBoxStruct := MailBox{authorizedUserInterKey[len(authorizedUserInterKey) - 16:]}

	// Change the MailBox struct into a byte slice
	mailBoxByte, err := json.Marshal(mailBoxStruct)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the MailBox struct")
	}

	err = userdata.CreateMailBox(userdata.Username, ownerHash, ownerPublicKey, authorizedUserInterKey, fileEncKey, fileMacKey, mailBoxByte)
	if err != nil {
		return err
	}


	var sharedStruct SharedFrom = SharedFrom{senderUsername, filename}

	
	authorizedToUUID, err := userdata.AccessAuthorizedTo(userdata.Username)
	if err != nil {
		return err
	}

	authorizedToVal, err := userdata.ConfirmAuthenticityHMAC(authorizedToUUID, macKey, encKey)
	if err != nil {
		return err
	}

	// Unmarshal the struct and recover information
	var authTo AuthorizedTo
	json.Unmarshal(authorizedToVal, &authTo)


	authTo.AuthoriedToList = append(authTo.AuthoriedToList, sharedStruct)
	
	//remake AuthorizedTo struct in DataStore
	authorizedToByte, err := json.Marshal(authTo)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the AuthorizedTo struct")
	}
	err = userdata.CreateAuthorizedTo(userdata.Username, userdata.Password, authorizedToByte)
	if err != nil {
		return err
	}
	
	// //after update, testing

	// authorizedToUUID, err = userdata.AccessAuthorizedTo(userdata.Username)
	// if err != nil {
	// 	return err
	// }

	// authorizedToVal, err = userdata.ConfirmAuthenticityHMAC(authorizedToUUID, macKey, encKey)
	// if err != nil {
	// 	return err
	// }

	// // Unmarshal the struct and recover information
	// json.Unmarshal(authorizedToVal, &authTo)

	// // AuthorizedTo []SharedFrom
	// authToList := authTo.AuthoriedToList
	// //print it
	// if true {
	// 	userlib.DebugMsg("!!!!!!!!!!!!!!!!!printing authTo")
	// 	userlib.DebugMsg("current user: %s", userdata.Username)

	// 	for i := 0; i < len(authToList); i++ {
	// 		sharee := authToList[i]
	// 		userlib.DebugMsg("sharee: un: %s, file: %x", sharee.Username, sharee.Filename)
	// 	}

	// 	// for i := 0; i < len(authToReal); i++ {
	// 	// 	sharee := authToReal[i]
	// 	// 	userlib.DebugMsg("sharee: un: %s, file: %s", sharee.Username, sharee.Filename)
	// 	// }
	// }

	// Delete the FileInvite entry
	userlib.DatastoreDelete(invitationPtr)

	return nil
}

func (userdata *User) RevokeAccess(fn string, recipientUsername string) error {

	// Generate macKey and encKey
	_, _, nameKey, err := GenerateKeys(userdata.Username, userdata.Password)
	// Error checking if GenerateKeys fails
	if err != nil {
		return errors.New("GenerateKeys fails")
	}

	filename, err := userdata.GetFileAlias(fn, nameKey)
	if err != nil {
		return err
	}

	publicKey, isFetched := userlib.KeystoreGet(userdata.Username + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return errors.New("Cannot retrieve Public Key")
	}

	verifyKey, isFetched := userlib.KeystoreGet(userdata.Username + "verifyKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return errors.New("Cannot retrieve Verify Key")
	}

	privateKey := userdata.PrivateKey

	// Check for AuthorizedUserIntermediate entry to determine whether the file already exists
	_, AuthorizedUserIntermediateEntry, err := AccessAuthorizedUserIntermediate(filename, nameKey, userdata.Username, publicKey)
	if err != nil {
		return err
	}

	// Check integrity and decrypt the retrieved AuthorizedUserIntermediate entry
	DecryptedAuthUserInter, err := userdata.ConfirmAuthenticityIntermediate(filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
	if err != nil {
		return err
	}

	var authorizedUserInter AuthorizedUserIntermediate
	json.Unmarshal(DecryptedAuthUserInter, &authorizedUserInter)

	authorizedUser, _, oldFileInterKey, err := userdata.GetAuthorizedUser(userdata.Username, filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
	if err != nil {
		return err
	}

	if authorizedUser.Owner != true {
		return errors.New("This user is not the file's owner, cannot revoke access")
	}

	oldFileEncKey := authorizedUser.FileEncKey
	oldFileMacKey := authorizedUser.FileMacKey
	oldFileNameKey := authorizedUser.FileNameKey
	oldOwnerHash := authorizedUser.OwnerHash

	// Generate new fileKey parts
	fileEncKey, fileMacKey, fileNameKey, fileInterKey, err := GenerateFileKeys()
	// Error checking if GenerateFileKeys fails
	if err != nil {
		return errors.New("GenerateFileKeys fails")
	}

	ownerHash := userlib.RandomBytes(8)

	//iterate through file nodes and reencrypt

	fileAccessKey, err := userdata.AccessFileAccess(userdata.Username, filename, oldFileInterKey)
	if err != nil {
		return err
	}

	// Decrypt the entry
	fileAccessValue, err := userdata.ConfirmAuthenticityHMAC(fileAccessKey, oldFileMacKey, oldFileEncKey)
	if err != nil {
		return err
	}

	// Unmarshal the struct and recover information
	var fileAccess FileAccess
	json.Unmarshal(fileAccessValue, &fileAccess)
	var authUsers []string = fileAccess.AuthorizedUsers

	//remake file
	err = userdata.ReencryptFileAndNodes(filename, fileEncKey, fileMacKey, fileNameKey, fileInterKey, ownerHash, oldFileEncKey, oldFileMacKey, oldFileNameKey, oldOwnerHash)
	//remake structs for self
	if err != nil {
		return err
	}
	err = userdata.RegenOwnerStructs(userdata.Username, recipientUsername, filename, fileEncKey, fileMacKey, fileNameKey, fileInterKey, ownerHash, oldFileEncKey, oldFileMacKey, oldFileInterKey, oldOwnerHash)

	if err != nil {
		return err
	}
 
	err = userdata.DeleteRevokedUserInvite(recipientUsername, filename, fileEncKey, fileMacKey, fileNameKey, fileInterKey, ownerHash, oldFileEncKey, oldFileMacKey, oldFileNameKey, oldFileInterKey, oldOwnerHash)
	if err != nil {
		return err
	}


	for i := 1; i < len(authUsers); i++ {
		sharee := authUsers[i]
		if sharee != recipientUsername {
			// Access the MailBox struct
			mailBoxKey, err := userdata.AccessMailBox(sharee, oldOwnerHash, publicKey)
			if err != nil {
			return errors.New("Cannot access Mailbox")
			}

			// Decrypt the entry
			encryptedMailbox, errHMAC := userdata.ConfirmMailBoxOnly(mailBoxKey, oldFileMacKey)

			userlib.DebugMsg("decrypting mailbox")
			mailBoxEntry, errDecrypt := userlib.PKEDec(userdata.PrivateKey, encryptedMailbox)

			if errHMAC != nil && errDecrypt == nil {
				return errors.New("failed confirminig mailbox auth")
				}

			if errHMAC == nil && errDecrypt == nil {
				userlib.DebugMsg("%s has a mailbox, going into regenhelperstruct", sharee)
				err1 := userdata.RecursivelyRegenHelperStructs(sharee, filename, fileEncKey,
					fileMacKey, fileNameKey, fileInterKey, ownerHash, oldFileEncKey, oldFileMacKey, oldFileNameKey, oldFileInterKey, oldOwnerHash, mailBoxEntry, mailBoxKey, publicKey)
				if err1 != nil {
					return err
				}
			}
		}
	}

	//dfs
	return nil
}
func (userdata *User) DeleteRevokedUserInvite(un string, filename []byte, fileEncKey []byte, fileMacKey []byte, fileNameKey []byte,
	fileInterKey []byte, ownerHash []byte, oldFileEncKey []byte, oldFileMacKey []byte, oldFileNameKey []byte, oldFileInterKey []byte, oldOwnerHash []byte) (err error) {
	fileAccessKey, err := userdata.AccessFileAccess(un, filename, oldFileInterKey)
	if err != nil {
		return err
	}
	
	// Decrypt the entry
	fileAccessValue, err := userdata.ConfirmAuthenticityHMAC(fileAccessKey, oldFileMacKey, oldFileEncKey)
	if err != nil {
		return err
	}

	// Unmarshal the struct and recover information
	var fileAccess FileAccess
	json.Unmarshal(fileAccessValue, &fileAccess)
	var authUsers []string = fileAccess.AuthorizedUsers

	for i := 1; i < len(authUsers); i++ {
		sharee := authUsers[i]
		revokedPublicKey, isFetched := userlib.KeystoreGet(sharee + "publicKey")
		// Error checking if cannot retrieve the KeyStore entry
		if !isFetched {
			return errors.New("Cannot retrieve Public Key")
		}
		fileInviteUUID, err := AccessFileInvite(filename, un, revokedPublicKey, oldFileNameKey)
		userlib.DebugMsg("Delete %s's file invite with uuid: %x, filename: %x, and revoked pk %x", sharee, fileInviteUUID, filename, revokedPublicKey)
		if err != nil {
		return nil
		}
		userlib.DatastoreDelete(fileInviteUUID)
	}
	return nil
}
func (userdata *User) RecursivelyRegenHelperStructs(un string, filename []byte, fileEncKey []byte, fileMacKey []byte, fileNameKey []byte,
	fileInterKey []byte, ownerHash []byte, oldFileEncKey []byte, oldFileMacKey []byte, oldFileNameKey []byte, oldFileInterKey []byte, oldOwnerHash []byte, mailBoxEntry []byte, mailBoxKey uuid.UUID, publicKey userlib.PKEEncKey) (err error) {
	//regen own struct then get it with new keys

	err = userdata.RegenHelperStructs(un, false, filename, fileEncKey, fileMacKey, fileNameKey, fileInterKey, ownerHash, oldFileEncKey, oldFileMacKey, oldFileInterKey, oldOwnerHash, mailBoxEntry, mailBoxKey, publicKey)
	if err != nil {
		return err
	}

	fileAccessKey, err := userdata.AccessFileAccess(un, filename, fileInterKey)
	if err != nil {
		return err
	}

	// Decrypt the entry
	fileAccessValue, err := userdata.ConfirmAuthenticityHMAC(fileAccessKey, fileMacKey, fileEncKey)
	if err != nil {
		return err
	}

	// Unmarshal the struct and recover information
	var fileAccess FileAccess
	json.Unmarshal(fileAccessValue, &fileAccess)
	var authUsers []string = fileAccess.AuthorizedUsers

	for i := 1; i < len(authUsers); i++ {
		sharee := authUsers[i]
		
			// Access the MailBox struct
			mailBoxKey, err := userdata.AccessMailBox(sharee, oldOwnerHash, publicKey)
			if err != nil {
			return errors.New("Cannot access Mailbox")
			}

			// Decrypt the entry
			encryptedMailbox, errHMAC := userdata.ConfirmMailBoxOnly(mailBoxKey, oldFileMacKey)

			userlib.DebugMsg("decrypting mailbox")
			mailBoxEntry, errDecrypt := userlib.PKEDec(userdata.PrivateKey, encryptedMailbox)

			if errHMAC != nil && errDecrypt == nil {
				return errors.New("failed confirminig mailbox auth")
				}

			if errHMAC == nil && errDecrypt == nil {
				userlib.DebugMsg("%s has a mailbox, going into regenhelperstruct", sharee)
				err1 := userdata.RecursivelyRegenHelperStructs(sharee, filename, fileEncKey,
					fileMacKey, fileNameKey, fileInterKey, ownerHash, oldFileEncKey, oldFileMacKey, oldFileNameKey, oldFileInterKey, oldOwnerHash, mailBoxEntry, mailBoxKey, publicKey)
				if err1 != nil {
					return err
				}
			}
	}
	return nil

}

/*
	HELPER METHODS
*/

// reencrypt a file and its nodes with the given keys
func (userdata *User) ReencryptFileAndNodes(filename []byte, fileEncKey []byte, fileMacKey []byte, fileNameKey []byte,
	fileInterKey []byte, ownerHash []byte, oldFileEncKey []byte, oldFileMacKey []byte, oldFileNameKey []byte, oldOwnerHash []byte) (err error) {
	// Generate macKey and encKey
	// Retrieve the file
	// Generate macKey and encKey
	un, pw := userdata.Username, userdata.Password
	_, _, nameKey, err := GenerateKeys(un, pw)
	// Error checking if GenerateKeys fails
	if err != nil {
		return errors.New("GenerateKeys fails")
	}

	publicKey, isFetched := userlib.KeystoreGet(un + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return errors.New("Cannot retrieve Public Key")
	}

	verifyKey, isFetched := userlib.KeystoreGet(un + "verifyKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return errors.New("Cannot retrieve Verify Key")
	}

	privateKey := userdata.PrivateKey

	// Check for AuthorizedUserIntermediate entry to determine whether the file already exists
	_, AuthorizedUserIntermediateEntry, err := AccessAuthorizedUserIntermediate(filename, nameKey, un, publicKey)
	if err != nil {
		return err
	}
	// Check integrity and decrypt the retrieved AuthorizedUserIntermediate entry
	DecryptedAuthUserInter, err := userdata.ConfirmAuthenticityIntermediate(filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
	if err != nil {
		return err
	}

	var authorizedUserInter AuthorizedUserIntermediate
	json.Unmarshal(DecryptedAuthUserInter, &authorizedUserInter)

	// authorizedUser, _, oldFileInterKey, err := userdata.GetAuthorizedUser(un, filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
	// if err != nil {
	// 	return err
	// }

	fileEntryContent, _, _, _, _, _, _, err := userdata.GetFile(filename, AuthorizedUserIntermediateEntry, privateKey, verifyKey)
	if err != nil {
		return err
	}

	// Re-encrypt the File struct, HMAC, and re-store in DataStore

	//delete file
	fileUUID, err := userdata.AccessFile(filename, oldOwnerHash, oldFileNameKey)
	userlib.DatastoreDelete(fileUUID)

	// Get the firstNode entry's key
	firstNode := fileEntryContent.FirstNodeUUID
	nodeNum := 1

	//get first node information SHOULD I NULL CHECK
	text, nextNode, contentUUID, _, err := userdata.AccessFileNodeContent(firstNode, oldFileNameKey, oldFileEncKey, oldFileMacKey)
	if err != nil || text == nil {
		return err
	}

	// Deleting the file node
	entryUUID, err := uuid.FromBytes((firstNode[len(firstNode)-16:]))
	userlib.DatastoreDelete(entryUUID)
	// Deeleting the file node's entry
	userlib.DatastoreDelete(contentUUID)

	//create new node
	createdNode, err := userdata.CreateNewFileNode(filename, fileNameKey, fileEncKey, fileMacKey, ownerHash, text, nodeNum)
	//set first of File struct
	fileEntryContent.FirstNodeUUID = createdNode
	fileEntryContent.LastNodeUUID = nil

	// var prevNode []byte = nil
	for nextNode != nil {
		text, nextnextNode, contentUUID, _, err := userdata.AccessFileNodeContent(nextNode, oldFileNameKey, fileEncKey, fileMacKey)
		if err != nil {
			return err
		}

		//get old UUID of this node and delete (also delete content)
		entryUUID, err := uuid.FromBytes((firstNode[len(firstNode)-16:]))
		userlib.DatastoreDelete(entryUUID)
		userlib.DatastoreDelete(contentUUID)

		//make new one
		//create new node
		createdNode, err := userdata.CreateNewFileNode(filename, fileNameKey, fileEncKey, fileMacKey, ownerHash, text, nodeNum)
		//set first of File struct
		fileEntryContent.LastNodeUUID = createdNode
		nextNode = nextnextNode
	}
	//nodes are remade

	//remake File struct in DataStore
	fileByte, err := json.Marshal(fileEntryContent)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the File struct")
	}
	err = userdata.CreateFile(filename, fileNameKey, fileEncKey, fileMacKey, ownerHash, fileByte)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) RegenOwnerStructs(un string, revokedUser string, filename []byte, fileEncKey []byte, fileMacKey []byte, fileNameKey []byte, fileInterKey []byte, ownerHash []byte, oldFileEncKey []byte, oldFileMacKey []byte, oldFileInterKey []byte, oldOwnerHash []byte) (err error) {
	// Generate macKey and encKey
	// _, _, nameKey, err := GenerateKeys(un, pw)
	// // Error checking if GenerateKeys fails
	// if err != nil {
	// 	return errors.New("GenerateKeys fails")
	// }
	nameKey := []byte("nothing")

	publicKey, isFetched := userlib.KeystoreGet(un + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return errors.New("Cannot retrieve Public Key")
	}

	// userlib.DebugMsg("regenownerstructs: getting %s's public key which is %s", userdata.Username, publicKey)

	//create new structs
	var newAuthorizedUserInter AuthorizedUserIntermediate = AuthorizedUserIntermediate{fileEncKey, fileMacKey, fileInterKey, ownerHash}
	var newAuthorizedUser AuthorizedUser = AuthorizedUser{filename, true, ownerHash, fileEncKey, fileMacKey, fileNameKey, fileInterKey, publicKey}

	// var newFileAccess FileAccess = FileAccess{} //we need to set this later
	fileHash := userlib.Hash([]byte(filename))
	userHash := userlib.Hash([]byte(un))
	intermediateHash := userlib.Hash([]byte("Intermediate"))
	combinedHash := append(fileHash, userHash...)
	combinedHash = append(combinedHash, intermediateHash...)
	combinedHash = userlib.Hash(combinedHash)

	//remake fileAccess

	fileAccessKey, err := userdata.AccessFileAccess(un, filename, oldFileInterKey)
	if err != nil {
		return err
	}

	// Decrypt the entry
	fileAccessValue, err := userdata.ConfirmAuthenticityHMAC(fileAccessKey, oldFileMacKey, oldFileEncKey)
	if err != nil {
		return err
	}

	// Unmarshal the struct and recover information
	var fileAccess FileAccess
	json.Unmarshal(fileAccessValue, &fileAccess)

	//delete old fileAccess
	userlib.DatastoreDelete(fileAccessKey)

	var i int
	var found bool

	for i = 0; i < len(fileAccess.AuthorizedUsers); i++ {
		sharee := fileAccess.AuthorizedUsers[i]
		if sharee == revokedUser {
			found = true
			break
		}
		// fmt.Println(arr[i])
	}
	if !found {
		return errors.New("user to revoke does not have access")
	}
	fileAccess.AuthorizedUsers = removeFromArray(fileAccess.AuthorizedUsers, i)

	fileAccessValue, err = json.Marshal(fileAccess)
	if err != nil {
		return err
	}

	//recreate
	err = userdata.CreateFileAccess(un, filename, fileInterKey, fileEncKey, fileMacKey, fileAccessValue)
	if err != nil {
		return err
	}

	//AUTH USER INTER STRUCT=================================
	// H(filename) || H(username) || H("Intermediate")

	// Create UUID(combinedHash)
	interUUID, err := uuid.FromBytes((combinedHash[len(combinedHash)-16:]))

	//delete old AuthorizedUserInter
	//TODO: SHOULD WE ERROR CHECK THAT DATASTORE ENTRY EXISTS
	userlib.DatastoreDelete(interUUID)

	authorizedUserInterByte, err := json.Marshal(newAuthorizedUserInter)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the Auth USer Inter struct")
	}
	//create new one
	//sign with owner's key
	err = userdata.CreateAuthorizedUserIntermediate(un, filename, nameKey, publicKey, fileInterKey, userdata.SignatureKey, authorizedUserInterByte)
	// Error checking if cannot create an AuthorizedUserIntermediate entry in DataStore
	if err != nil {
		return err
	}

	//AUTH USER STRUCT=================================
	authorizedUserUUID, _, err := AccessAuthorizedUser(ownerHash, un, oldFileInterKey)
	if err != nil {
		return err
	}
	//delete

	userlib.DatastoreDelete(authorizedUserUUID)

	authUserByte, err := json.Marshal(newAuthorizedUser)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the AuthorizedUser struct")
	}

	err = userdata.CreateAuthorizedUser(un, ownerHash, fileInterKey, fileEncKey, fileMacKey, authUserByte)

	return nil
}

func removeFromArray(arr []string, i int) []string {
	copy(arr[i:], arr[i+1:])
	//return
	return arr[:len(arr)-1]
}

// reencrypt a file's AuthorizedUserInter, AuthorizedUser, FileAccess structs
// may not be called by owner of structs (but called by owner of file)
func (userdata *User) RegenHelperStructs(un string, owner bool, filename []byte, fileEncKey []byte, fileMacKey []byte, fileNameKey []byte, fileInterKey []byte, ownerHash []byte, oldFileEncKey []byte, oldFileMacKey []byte, oldFileInterKey []byte, oldOwnerHash []byte, mailBoxEntry []byte,
	mailBoxKey uuid.UUID, publicKey userlib.PKEEncKey) (err error) {
	// fmt.Println("calling regenhelper on " + un) //expect alice
	//userlib.DebugMsg("\n\n!!!!!!!!!!!calling regen helper on %s by %s", un, userdata.Username)

	shareePublicKey, isFetched := userlib.KeystoreGet(un + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !isFetched {
		return errors.New("Cannot retrieve Public Key")
	}

	userlib.DebugMsg("unmarshalling mailbox bytes")
	// Unmarshal the struct and recover information
	var mailBox MailBox
	json.Unmarshal(mailBoxEntry, &mailBox)
	userlib.DebugMsg("The mailbox struct: %x", mailBox)

	authorizedUserInterKey := mailBox.InterUUID
	// userlib.DebugMsg("found %s's authuserinter key in mailbox; access: %s", un, userdata.Username)
	// userlib.DebugMsg("The authorizedUserInter key is %s", authorizedUserInterKey)
	//create new structs
	var newAuthorizedUserInter AuthorizedUserIntermediate = AuthorizedUserIntermediate{fileEncKey, fileMacKey, fileInterKey, ownerHash}

	authorizedUserInterByte, err := json.Marshal(newAuthorizedUserInter)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the Auth USer Inter struct")
	}
	// Create UUID(entryKey)
	userlib.DebugMsg("regen; trying to find interUUID: authorizedUserInterKey: %x, len: %d", authorizedUserInterKey, len(authorizedUserInterKey))

	// interUUID, err := uuid.FromBytes(authorizedUserInterKey)
	// // Error checking if cannot create userUUID from entryKey
	// if err != nil {
	// 	return errors.New("Cannot create AuthorizedUserInter's UUID")
	// }

	// userlib.DatastoreDelete(interUUID)
	// userlib.DebugMsg("deleting old userinter struct..?")
	//create new one
	//sign with owner's key
	err = userdata.SetAuthorizedUserInter(un, authorizedUserInterKey, shareePublicKey, userdata.SignatureKey, authorizedUserInterByte)
	// Error checking if cannot create an AuthorizedUserIntermediate entry in DataStore
	if err != nil {
		return err
	}

	userlib.DatastoreDelete(mailBoxKey)


	

	var newAuthorizedUser AuthorizedUser = AuthorizedUser{filename, owner, ownerHash, fileEncKey, fileMacKey, fileNameKey, fileInterKey, publicKey}
	//var newMailBox MailBox = MailBox{authorizedUserInterKey}

	//AUTH USER STRUCT=================================
	// authorizedUserKey := mailBox.AuthUserUUID
	// authorizedUserUUID, err := uuid.FromBytes(authorizedUserKey)
	// if err != nil {
	// 	return err
	// }
	// //delete

	// userlib.DatastoreDelete(authorizedUserUUID)

	authUserByte, err := json.Marshal(newAuthorizedUser)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the AuthorizedUser struct")
	}

	err = userdata.CreateAuthorizedUser(un, ownerHash, fileInterKey, fileEncKey, fileMacKey, authUserByte)
	if err != nil {
		return err
	}

	//remake fileAccess

	fileAccessKey, err := userdata.AccessFileAccess(un, filename, oldFileInterKey)
	if err != nil {
		return err
	}

	// Decrypt the entry
	fileAccessValue, err := userdata.ConfirmAuthenticityHMAC(fileAccessKey, oldFileMacKey, oldFileEncKey)
	if err != nil {
		return err
	}

	// Unmarshal the struct and recover information
	var fileAccess FileAccess
	json.Unmarshal(fileAccessValue, &fileAccess)

	//delete old fileAccess
	userlib.DatastoreDelete(fileAccessKey)

	//recreate
	err = userdata.CreateFileAccess(un, filename, fileInterKey, fileEncKey, fileMacKey, fileAccessValue)
	if err != nil {
		return err
	}


	userlib.DebugMsg("reached the end of regen")

	return nil
}

func (userdata *User) GetFileAlias(fn string, nameKey []byte) ([]byte, error) {
	res, err := userlib.HashKDF(nameKey, []byte(fn))
	return res, err
}


func (userdata *User) UpdateUserStruct(username string, password string, content []byte) (err error) {

	// Recompute GenerateKeys
	macKey, encKey, _, err := GenerateKeys(username, password)

	// Error checking if GenerateKeys fails
	if err != nil {
		return errors.New("GenerateKeys fails")
	}

	// Create Hash(username)
	usernameHash := userlib.Hash([]byte(username))
	// Create UUID(Hash(username))
	userUUID, err := uuid.FromBytes((usernameHash[:16]))

	// Error checking if cannot create userUUID from usernameHash
	if err != nil {
		return errors.New("Cannot create this userUUID")
	}

	// Create Enc(User struct)
	iv := userlib.RandomBytes(16)
	encryptedUser := userlib.SymEnc(encKey, iv, content)

	// Create HMAC(Enc(User struct)
	HMACEncryptedUser, err := userlib.HMACEval(macKey, encryptedUser)
	// Error checking if HMACEval fails
	if err != nil {
		return errors.New("Cannot HMAC the encrypted User struct")
	}

	// Storing (userUUID, Enc(User struct) || HMAC(Enc(User struct)) in DataStore
	userlib.DatastoreSet(userUUID, append(encryptedUser, HMACEncryptedUser...))

	return nil
}

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
func (userdata *User) ConfirmMailBoxOnly(entryKey userlib.UUID, macKey []byte) (content []byte, err error) {
	// Fetching the DataStore entry
	dataStoreEntry, isFetched := userlib.DatastoreGet(entryKey)
	// Error checking if cannot retrieve the DataStore entry
	if !isFetched {
		return nil, errors.New("Cannot retrieve DataStore entry")
	}
	//userlib.DebugMsg("the value of the mailbox is %x:", dataStoreEntry)
	// Retrieve Enc(struct)
	encryptedStruct := dataStoreEntry[:len(dataStoreEntry)-64]
	//userlib.DebugMsg("the value of the encrypted mailbox is %x", encryptedStruct)
	// Retrieve HMAC(Enc(struct))
	HMACEncryptedStruct := dataStoreEntry[len(dataStoreEntry)-64:]
	//userlib.DebugMsg("the value of the hmac mailbox is %x", HMACEncryptedStruct)

	//userlib.DebugMsg("The file mac key for this mailbox is %x", macKey)

	// Create HMAC(Enc(struct) with the regenerated macKey
	newHMACEncryptedStruct, err := userlib.HMACEval(macKey, encryptedStruct)
	// Error checking if HMACEval fails
	if err != nil {
		return nil, errors.New("Cannot HMAC the encrypted struct")
	}

	// Confirm authenticity using HMACEqual()
	if !userlib.HMACEqual(HMACEncryptedStruct, newHMACEncryptedStruct) {
		return nil, errors.New("Data has been modifiedskdjfkms")
	}

	return encryptedStruct, nil
}

// Helper to confirm authenticity (data has not been tampered with)
func (userdata *User) ConfirmAuthenticityHMAC(entryKey userlib.UUID, macKey []byte, encKey []byte) (content []byte, err error) {

	// Fetching the DataStore entry
	dataStoreEntry, isFetched := userlib.DatastoreGet(entryKey)
	// Error checking if cannot retrieve the DataStore entry
	if !isFetched {
		return nil, errors.New("Cannot retrieve DataStore entry")
	}

	// Retrieve Enc(struct)
	encryptedStruct := dataStoreEntry[:len(dataStoreEntry)-64]

	// Retrieve HMAC(Enc(struct))
	HMACEncryptedStruct := dataStoreEntry[len(dataStoreEntry)-64:]

	// Create HMAC(Enc(struct) with the regenerated macKey
	newHMACEncryptedStruct, err := userlib.HMACEval(macKey, encryptedStruct)
	// Error checking if HMACEval fails
	if err != nil {
		return nil, errors.New("Cannot HMAC the encrypted struct")
	}

	// Confirm authenticity using HMACEqual()
	if !userlib.HMACEqual(HMACEncryptedStruct, newHMACEncryptedStruct) {
		return nil, errors.New("Data has been modified")
	}

	// Decrypt the encryptedStruct
	decryptedStruct := userlib.SymDec(encKey, encryptedStruct)

	return decryptedStruct, nil
}

// Helper function to check and decrypt the retrieved AuthorizedUserIntermediate
func (userdata *User) ConfirmAuthenticityIntermediate(filename []byte, entryValue []byte, privateKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey) (content []byte, err error) {
	// if filename == "eveFile.tx" {
	// 	// //print debug
	// 	// userlib.DebugMsg("confirming authenticity: userHash=%x, combinedHash= %x, recipientUN = %s, owner PK = %s",
	// 	// 	userHash, combinedHash, recipientUsername, ownerPublicKey)

	// }
	publicKey, fetched := userlib.KeystoreGet(userdata.Username + "publicKey")
	// Error checking if cannot retrieve the KeyStore entry
	if !fetched {
		return nil, errors.New("Cannot retrieve Public Key")
	}
	userlib.DebugMsg("The public key of %s is %s", userdata.Username, publicKey)
	var ownerVerifyKey userlib.DSVerifyKey
	var isFetched bool = false
	// Retrieve RSA(key = RSA public key, value = AuthorizedUserIntermediate struct)
	encryptedStruct := entryValue[:len(entryValue)-256]

	// Retrieve RSA_SIG(msg = RSA(AuthorizedUserIntermediate struct), key = RSA Signature key)
	signature := entryValue[len(entryValue)-256:]

	// Generate macKey and encKey
	macKey, encKey, _, err := GenerateKeys(userdata.Username, userdata.Password)
	// Error checking if GenerateKeys fails
	if err != nil {
		return nil,  errors.New("GenerateKeys fails")
	}

	// Access the user's authorizedTo struct
	authorizedToUUID, err := userdata.AccessAuthorizedTo(userdata.Username)
	if err != nil {
		return nil, err
	}

	authorizedToValue, err := userdata.ConfirmAuthenticityHMAC(authorizedToUUID, macKey, encKey)
	if err != nil {
		return nil, err
	}
	var authorizedTo AuthorizedTo
	json.Unmarshal(authorizedToValue, &authorizedTo)

	// AuthorizedTo []SharedFrom
	authTo := authorizedTo.AuthoriedToList
	//print it
	if true {
		userlib.DebugMsg("printing authTo")
		userlib.DebugMsg("current user: %s", userdata.Username)
		for i := 0; i < len(authTo); i++ {
			sharer := authTo[i]
			userlib.DebugMsg("sharer un: %s, file: %x", sharer.Username, sharer.Filename)
		}
	}

	for i := 0; i < len(authTo); i++ {
		sharer := authTo[i]
		if hex.EncodeToString(sharer.Filename) == hex.EncodeToString(filename) {
			ownerVerifyKey, isFetched = userlib.KeystoreGet(sharer.Username + "verifyKey")
			// Error checking if cannot retrieve the KeyStore entry
			if !isFetched {
				return nil, errors.New("Cannot retrieve Verify Key")
			}
		}
		// fmt.Println(arr[i])
	}
	// Use the RSA public key to verify the signature
	var err1 error
	var err2 error
	if isFetched {
		err1 = userlib.DSVerify(ownerVerifyKey, encryptedStruct, signature)
	} else {
		err2 = userlib.DSVerify(verifyKey, encryptedStruct, signature)
	}
	// Unmarshal the struct and recover information

	if err1 != nil && err2 != nil {
		return nil, errors.New("Cannot verify the signature of this AuthorizedUserIntermediate")
	}

	// Decrypt RSA(key = RSA public key, value = AuthorizedUserIntermediate struct)
	content, err = userlib.PKEDec(privateKey, encryptedStruct)
	if err != nil {
		return nil, errors.New("Cannot decrypt this AuthorizedUserIntermediate entry")
	}

	return content, nil
}

// Helper function to access the FileNodeContent struct in DataStore
func (userdata *User) AccessFileNodeContent(entryKey []byte, fileNameKey []byte, fileEncKey []byte, fileMacKey []byte) (
	content []byte, nextNode []byte, contentUUID userlib.UUID, nodeNum int, err error) {
	// key: HKDF(key = fileNameKey, value = H(filename) || ownerHash || H("fileNode[num]"))

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[len(entryKey)-16:]))
	// Error checking if cannot create UUID from entryKey
	if err != nil {
		return nil, nil, uuid.New(), 0, errors.New("Cannot create FileNode's UUID")
	}

	// Decrypt the retrieved FileNode entry
	decryptedFileNode, err := userdata.ConfirmAuthenticityHMAC(entryUUID, fileMacKey, fileEncKey)
	if err != nil {
		return nil, nil, uuid.New(), 0, err
	}

	// Unmarshal the struct and recover information
	var fileNode FileNode
	json.Unmarshal(decryptedFileNode, &fileNode)

	nodeNum = fileNode.NodeNum
	contentKey := fileNode.TextUUID
	nextNode = fileNode.NextNodeUUID

	// Create UUID(contentKey)
	contentUUID, err = uuid.FromBytes((contentKey[len(contentKey)-16:]))
	// Error checking if cannot create UUID from contentKey
	if err != nil {
		return nil, nil, uuid.New(), 0, errors.New("Cannot create FileNodeContent's UUID")
	}

	// Decrypt the FileNodeContent entry
	decryptedFileNodeContent, err := userdata.ConfirmAuthenticityHMAC(contentUUID, fileMacKey, fileEncKey)
	if err != nil {
		return nil, nil, uuid.New(), 0, err
	}

	content = decryptedFileNodeContent

	return content, nextNode, contentUUID, nodeNum, err
}

// Helper function to access the FileNode struct in DataStore
func (userdata *User) AccessFileNode(entryKey []byte, fileNameKey []byte, fileEncKey []byte, fileMacKey []byte) (fileNode FileNode, err error) {
	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[len(entryKey)-16:]))
	// Error checking if cannot create UUID from entryKey
	if err != nil {
		return fileNode, errors.New("Cannot create FileNode's UUID")
	}

	// Decrypt the retrieved FileNode entry
	decryptedFileNode, err := userdata.ConfirmAuthenticityHMAC(entryUUID, fileMacKey, fileEncKey)
	if err != nil {
		return fileNode, err
	}

	// Unmarshal the struct and recover information
	json.Unmarshal(decryptedFileNode, &fileNode)

	return fileNode, nil
}


// Helper function to access the MailBox struct in DataStore
func (userdata *User) AccessMailBox(recipientUsername string,
	ownerHash []byte, ownerPublicKey userlib.PKEEncKey) (entryUUID userlib.UUID, err error) {
	// key: PKE(hash(ownerHash || recipient name))
	// value: Enc(key = fileEncKey, value = AuthorizedUser struct) ||
	// HMAC(Enc(key = fileMacKey, value = AuthorizedUser struct))

	userHash := userlib.Hash([]byte(recipientUsername))
	combinedHash := append(ownerHash, userHash...)
	combinedHash = userlib.Hash(combinedHash)

	userlib.DebugMsg("accessing mailbox regenerating values: userHash=%x, combinedHash= %x, recipientUN = %s, owner PK = %s",
		userHash, combinedHash, recipientUsername, ownerPublicKey)

	entryKey := combinedHash

	// Create UUID(entryKey)
	entryUUID, err = uuid.FromBytes((entryKey[len(entryKey)-16:]))
	// Error checking if cannot create userUUID from entryKey
	if err != nil {
		return uuid.New(), errors.New("Cannot create MailBox's UUID")
	}

	return entryUUID, nil
}

// Helper function to access the FileAccess struct in DataStore
func (userdata *User) AccessFileAccess(username string, filename []byte, fileInterKey []byte) (entryUUID userlib.UUID, err error) {

	// key: HKDF(key = fileInterKey, value = H(filename) || H(username) || H("fileAccess"))
	// value: Enc(key = fileEncKey, value = FileAccess struct)
	// || HMAC(Enc(key = fileMacKey, value = FileAccess struct))

	// H(filename) || H(username) || H("fileAccess")
	fileHash := userlib.Hash([]byte(filename))
	userHash := userlib.Hash([]byte(username))
	fileAccessHash := userlib.Hash([]byte("fileAccess"))
	combinedHash := append(fileHash, userHash...)
	combinedHash = append(combinedHash, fileAccessHash...)
	combinedHash = userlib.Hash(combinedHash)

	entryKey, err := userlib.HashKDF(fileInterKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return uuid.New(), errors.New("Cannot create the File Access's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err = uuid.FromBytes((entryKey[len(entryKey)-16:]))
	// Error checking if cannot create userUUID from entryKey
	if err != nil {
		return uuid.New(), errors.New("Cannot create File Access's UUID")
	}

	return entryUUID, nil
}

// Helper function to access the File struct in DataStore
func (userdata *User) AccessFile(filename []byte, ownerHash []byte, fileNameKey []byte) (entryUUID userlib.UUID, err error) {
	// key: HKDF(key = fileNameKey, value = H(filename) || ownerHash || H("file"))

	// H(filename) || ownerHash || H("file")
	fileHash := userlib.Hash([]byte(filename))
	fileStringHash := userlib.Hash([]byte("file"))
	combinedHash := append(fileHash, ownerHash...)
	combinedHash = append(combinedHash, fileStringHash...)
	combinedHash = userlib.Hash(combinedHash)

	entryKey, err := userlib.HashKDF(fileNameKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return uuid.New(), errors.New("Cannot create the File's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err = uuid.FromBytes((entryKey[len(entryKey)-16:]))
	// Error checking if cannot create UUID from entryKey
	if err != nil {
		return uuid.New(), errors.New("Cannot create File's UUID")
	}

	return entryUUID, nil

}

// Helper function to access the AuthorizedUser struct in DataStore
func AccessAuthorizedUser(ownerHash []byte, username string, fileInterKey []byte) (entryUUID userlib.UUID, entryKey []byte, err error) {
	// key: HKDF(key = fileInterKey, value = H(filename) || H(username) || H("authUser"))

	// H(filename) || H(username) || H("authUser")
	userHash := userlib.Hash([]byte(username))
	authUserHash := userlib.Hash([]byte("authUser"))
	combinedHash := append(ownerHash, userHash...)
	combinedHash = append(combinedHash, authUserHash...)
	combinedHash = userlib.Hash(combinedHash)

	entryKey, err = userlib.HashKDF(fileInterKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return uuid.New(), nil, errors.New("Cannot create the Authorized User's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err = uuid.FromBytes((entryKey[len(entryKey)-16:]))
	// Error checking if cannot create UUID from entryKey
	if err != nil {
		return uuid.New(), nil, errors.New("Cannot create Authorized User's UUID")
	}

	return entryUUID, entryKey[len(entryKey)-16:], nil
}

func AccessFileInvite(filename []byte, senderUsername string, recipientPublicKey userlib.PKEEncKey, fileNameKey []byte) (entryUUID uuid.UUID, err error) {

	
	// key: HKDF(key = fileNameKey, value = H(filename) || H(username) || H("authUser"))
	// value: RSA(struct FileInvite, recipient.pubKey)||
	// Sign(RSA(struct FileInvite, recipient.pubKey), senderSignatureKey)

	// H(filename) || H(senderUsername) || ownerHash
	fileHash := userlib.Hash([]byte(filename))
	senderUserHash := userlib.Hash([]byte(senderUsername))
	combinedHash := append(fileHash, senderUserHash...)
	combinedHash = userlib.Hash(combinedHash)

	entryKey, err := userlib.HashKDF(fileNameKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return uuid.New(), errors.New("Cannot create the File Invite entry key")
	}


	// Create UUID(entryKey)
	entryUUID, err = uuid.FromBytes((entryKey[len(entryKey)-16:]))
	// Error checking if cannot create userUUID from entryKey
	if err != nil {
		return uuid.New(), errors.New("Cannot create File Invite's UUID")
	}

	return entryUUID, nil
}


// Helper function to access the AuthorizedUserIntermediate struct in DataStore
func AccessAuthorizedUserIntermediate(filename []byte, nameKey []byte, username string, publicKey userlib.PKEEncKey) (entryKey []byte, structData []byte, err error) {
	// key: "H(filename) || H(username) || H("Intermediate"))"

	// H(filename) || H(username) || H("Intermediate")
	fileHash := userlib.Hash([]byte(filename))
	userHash := userlib.Hash([]byte(username))
	intermediateHash := userlib.Hash([]byte("Intermediate"))
	combinedHash := append(fileHash, userHash...)
	combinedHash = append(combinedHash, intermediateHash...)
	combinedHash = userlib.Hash(combinedHash)

	// Create UUID(authorizedUserIntermediateEntryKey)
	authorizedUserIntermediateUUID, err := uuid.FromBytes((combinedHash[len(combinedHash)-16:]))
	// Error checking if cannot create UUID from usernameHash
	if err != nil {
		return nil, nil, errors.New("Cannot create authorizedUserIntermediateUUID ")
	}

	authorizedUserIntermediateEntry, isFetched := userlib.DatastoreGet(authorizedUserIntermediateUUID)
	// Error checking if cannot retrieve the DataStore entry
	if !isFetched {
		return nil, nil, errors.New("Cannot retrieve DataStore entry")
	}

	return combinedHash[len(combinedHash)-16:], authorizedUserIntermediateEntry, nil
}
func (userdata *User) AccessAuthorizedTo(username string) (entryUUID uuid.UUID, err error) {
	
	// Error checking if GenerateKeys fails
	if err != nil {
		return uuid.New(), errors.New("GenerateKeys fails")
	}

	// Create Hash(username)
	authorizedToHash := userlib.Hash([]byte(username + "AuthorizedTo"))
	// Create UUID(Hash(username))
	authorizedToUUID, err := uuid.FromBytes((authorizedToHash[:16]))

	// Error checking if cannot create userUUID from usernameHash
	if err != nil {
		return uuid.New(), errors.New("Cannot create this authorizedToUUID")
	}

	return authorizedToUUID, nil
}


// Helper function to store the AuthorizedTo entry in DataStore
func (userdata *User) CreateAuthorizedTo(username string, password string, content []byte) (err error) {
	// Recompute GenerateKeys
	macKey, encKey, _, err := GenerateKeys(username, password)

	// Error checking if GenerateKeys fails
	if err != nil {
		return errors.New("GenerateKeys fails")
	}

	// Create Hash(username)
	authorizedToHash := userlib.Hash([]byte(username + "AuthorizedTo"))
	// Create UUID(Hash(username))
	authorizedToUUID, err := uuid.FromBytes((authorizedToHash[:16]))

	// Error checking if cannot create userUUID from usernameHash
	if err != nil {
		return errors.New("Cannot create this authorizedToUUID")
	}

	// Create Enc(Authorized To)
	iv := userlib.RandomBytes(16)
	encryptedAuthorizedTo := userlib.SymEnc(encKey, iv, content)

	// Create HMAC(Enc(User struct)
	HMACEncryptedAuthorizedTo, err := userlib.HMACEval(macKey, encryptedAuthorizedTo)
	// Error checking if HMACEval fails
	if err != nil {
		return errors.New("Cannot HMAC the encrypted AuthorizedTo struct")
	}

	// Storing (userUUID, Enc(User struct) || HMAC(Enc(User struct)) in DataStore
	userlib.DatastoreSet(authorizedToUUID, append(encryptedAuthorizedTo, HMACEncryptedAuthorizedTo...))

	return nil
}

// Helper function to create a MailBox entry in DataStore
// username here is the owner of the struct
// owner public key is fileowner's public key
func (userdata *User) CreateMailBox(username string, ownerHash []byte,
	ownerPublicKey userlib.PKEEncKey, authorizedUserInterKey []byte, fileEncKey []byte,
	fileMacKey []byte, mailBox []byte) (err error) {

	// key: PKE(hash(ownerHash || recipient name))
	// value: ENC(fileEncKey, val = authorizeduserinterkey) ||
	// HMAC(rsa(key = fileMacKey, value = authorizeduserinterkey))

	userHash := userlib.Hash([]byte(username))
	combinedHash := append(ownerHash, userHash...)
	combinedHash = userlib.Hash(combinedHash)

	entryKey := combinedHash

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[len(entryKey)-16:]))
	// Error checking if cannot create userUUID from entryKey
	if err != nil {
		return errors.New("Cannot create MailBox's UUID")
	}

	// Enc(owner public key, value = authorizeduserkey)
	encryptedMailBox, err := userlib.PKEEnc(ownerPublicKey, mailBox)
	if err != nil {
		return errors.New("Cannot use the owner's public key to encrypy the mailBox")
	}
	// HMAC(Enc(key = fileMacKey, value = authorizedUserKey))
	HMACEncryptedMailBox, err := userlib.HMACEval(fileMacKey, encryptedMailBox)
	// Error checking if HMACEval fails
	if err != nil {
		return errors.New("Cannot HMAC the encrypted struct")
	}

	entryValue := append(encryptedMailBox, HMACEncryptedMailBox...)
	// Storing (key, value) in DataStore
	userlib.DatastoreSet(entryUUID, entryValue)

	return nil
}

// Helper function to create an AuthorizedUserIntermediate entry in DataStore
// can be called by others
// username is owner of struct, pk enc key is owner of struc, signkey is owner of struct or owner of file
func (userdata *User) CreateAuthorizedUserIntermediate(username string, filename []byte, nameKey []byte, publicKey userlib.PKEEncKey, fileInterKey []byte, signatureKey userlib.DSSignKey, authorizedUserIntermediate []byte) (err error) {
	// key: "H(filename) || H(username) || H("Intermediate")"
	// value: RSA(key = RSA public key, value = AuthorizedUserIntermediate struct) || RSA_SIG(msg = RSA(AuthorizedUserIntermediate struct), key = RSA Signature key)

	// OwnerHash || H(username) || H("Intermediate")
	fileHash := userlib.Hash([]byte(filename))
	userHash := userlib.Hash([]byte(username))
	intermediateHash := userlib.Hash([]byte("Intermediate"))
	combinedHash := append(fileHash, userHash...)
	combinedHash = append(combinedHash, intermediateHash...)
	combinedHash = userlib.Hash(combinedHash)

	// Create UUID(combinedHash)
	entryUUID, err := uuid.FromBytes((combinedHash[len(combinedHash)-16:]))
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
func (userdata *User) CreateAuthorizedUser(username string, ownerHash []byte, fileInterKey []byte, fileEncKey []byte,
	fileMacKey []byte, authorizedUser []byte) (err error) {

	// key: HKDF(key = fileInterKey, value = H(filename) || H(username) || H("authUser"))
	// value: Enc(key = fileEncKey, value = AuthorizedUser struct) ||
	// HMAC(Enc(key = fileMacKey, value = AuthorizedUser struct))

	// ownerHash || H(username) || H("authUser")
	
	userHash := userlib.Hash([]byte(username))
	authUserHash := userlib.Hash([]byte("authUser"))
	combinedHash := append(ownerHash, userHash...)
	combinedHash = append(combinedHash, authUserHash...)
	combinedHash = userlib.Hash(combinedHash)

	entryKey, err := userlib.HashKDF(fileInterKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return errors.New("Cannot create the Authorized User's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[len(entryKey)-16:]))
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
	userlib.DebugMsg("Creating an Authorized User for %s with entryUUID as %x, ownerHash: %x, fileInterKey: %x, fileEncKey: %x, fileMacKey: %x", username, entryUUID, ownerHash, fileInterKey, fileEncKey, fileMacKey )
	return nil
}

// Helper function to create a FileInvite entry in DataStore
func CreateFileInvite(filename []byte, senderUsername string, recipientPublicKey userlib.PKEEncKey, fileNameKey []byte,
	senderSignatureKey userlib.DSSignKey, fileInvite []byte) (entryUUID uuid.UUID, err error) {

	// key: HKDF(key = fileNameKey, value = H(filename) || H(username) || H("authUser"))
	// value: RSA(struct FileInvite, recipient.pubKey)||
	// Sign(RSA(struct FileInvite, recipient.pubKey), senderSignatureKey)

	// H(filename) || H(senderUsername) || ownerHash
	fileHash := userlib.Hash([]byte(filename))
	senderUserHash := userlib.Hash([]byte(senderUsername))
	combinedHash := append(fileHash, senderUserHash...)
	combinedHash = userlib.Hash(combinedHash)

	entryKey, err := userlib.HashKDF(fileNameKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return uuid.New(), errors.New("Cannot create the File Invite entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err = uuid.FromBytes((entryKey[len(entryKey)-16:]))
	// Error checking if cannot create userUUID from entryKey
	if err != nil {
		return uuid.New(), errors.New("Cannot create File Invite's UUID")
	}

	// RSA(struct FileInvite, recipient.pubKey)
	entryRSA, err := userlib.PKEEnc(recipientPublicKey, fileInvite)
	// Error checking if cannot create the entryRSA
	if err != nil {
		return uuid.New(), errors.New("Cannot use RSA public key to encrypt the FileInvite entry")
	}

	// Sign(RSA(struct FileInvite, recipient.pubKey), senderSignatureKey)
	entryRSASignature, err := userlib.DSSign(senderSignatureKey, entryRSA)
	// Error checking if cannot create the RSA Signature
	if err != nil {
		return uuid.New(), errors.New("Cannot create the RSA Signature")
	}

	// RSA(key = RSA public key, value = fileInterKey) || RSA_SIG(msg = RSA, key = RSA Signature key)
	entryValue := append(entryRSA, entryRSASignature...)

	// Storing (key, value) in DataStore
	userlib.DatastoreSet(entryUUID, entryValue)
	userlib.DebugMsg("The file invite from %s has the UUID of %x", senderUsername, entryUUID)
	userlib.DebugMsg("The file invite from %s has the filename of %x and recipient pk of %x", senderUsername, filename, recipientPublicKey)
	return entryUUID, nil
}

// Helper function to create a FileAccess entry in DataStore
func (userdata *User) CreateFileAccess(username string, filename []byte,
	fileInterKey []byte, fileEncKey []byte, fileMacKey []byte, fileAccess []byte) (err error) {

	// key: HKDF(key = fileInterKey, value = H(filename) || H(username) || H("fileAccess"))
	// value: Enc(key = fileEncKey, value = FileAccess struct)
	// || HMAC(Enc(key = fileMacKey, value = FileAccess struct))

	// H(filename) || H(username) || H("fileAccess")
	fileHash := userlib.Hash([]byte(filename))
	userHash := userlib.Hash([]byte(username))
	fileAccessHash := userlib.Hash([]byte("fileAccess"))
	combinedHash := append(fileHash, userHash...)
	combinedHash = append(combinedHash, fileAccessHash...)
	combinedHash = userlib.Hash(combinedHash)

	entryKey, err := userlib.HashKDF(fileInterKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return errors.New("Cannot create the File Access's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[len(entryKey)-16:]))
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
func (userdata *User) CreateFile(filename []byte, fileNameKey []byte,
	fileEncKey []byte, fileMacKey []byte, ownerHash []byte, file []byte) (err error) {

	// key: HKDF(key = fileNameKey, value = H(filename) || ownerHash || H("file"))
	// value: Enc(key = fileEncKey, value = File struct)
	// || HMAC(Enc(key = fileMacKey, value = File struct))

	// H(filename) || ownerHash || H("file")
	fileHash := userlib.Hash([]byte(filename))
	fileStringHash := userlib.Hash([]byte("file"))
	combinedHash := append(fileHash, ownerHash...)
	combinedHash = append(combinedHash, fileStringHash...)
	combinedHash = userlib.Hash(combinedHash)

	entryKey, err := userlib.HashKDF(fileNameKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return errors.New("Cannot create the File's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[len(entryKey)-16:]))
	// entryUUID := uuid.New()
	// Error checking if cannot create userUUID from entryKey
	// if err != nil {
	// 	return uuid.New(), errors.New("Cannot create File's UUID")
	// }

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

// Helper function to re-set an existing AuthorizedUserInter entry in DataStore
// assumes caller is owner of file
func (userdata *User) SetAuthorizedUserInter(username string, entryKey []byte, publicKey userlib.PKEEncKey, signatureKey userlib.DSSignKey, authorizedUserIntermediate []byte) (err error) {

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes(entryKey)
	// Error checking if cannot create userUUID from entryKey
	if err != nil {
		return errors.New("Cannot create AuthorizedUserInter's UUID")
	}

	// RSA(key = RSA public key, value = AuthorizedUserIntermediate struct)
	entryRSA, err := userlib.PKEEnc(publicKey, authorizedUserIntermediate)
	// Error checking if cannot create the entryRSA
	if err != nil {
		return errors.New("Cannot use RSA public key to encrypt the AuthorizedUserIntermediate entry")
	}
	userlib.DebugMsg("The public key used for rencrypting %s's authoruserinter is %s", username, publicKey)

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

// Helper function to re-set an existing FileNode entry in DataStore
// assumes caller is owner of file
func (userdata *User) CreateFileNode(filename []byte, fileNameKey []byte,
	fileEncKey []byte, fileMacKey []byte, ownerHash []byte, nodeNum int, fileNode []byte) (err error) {
	nodeNumString := strconv.Itoa(nodeNum)
	// H(filename) || OwnerHash || H("fileNode[num]")
	fileHash := userlib.Hash([]byte(filename))
	fileNodeNum := userlib.Hash([]byte("fileNode" + nodeNumString))
	combinedHash := append(fileHash, ownerHash...)
	combinedHash = append(combinedHash, fileNodeNum...)
	combinedHash = userlib.Hash(combinedHash)

	entryKey, err := userlib.HashKDF(fileNameKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return errors.New("Cannot create the File Node's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[len(entryKey)-16:]))
	// Error checking if cannot create userUUID from entryKey
	if err != nil {
		return errors.New("Cannot create File Node's UUID")
	}

	// Enc(key = fileEncKey, value = File struct)
	iv := userlib.RandomBytes(16)
	encryptedFile := userlib.SymEnc(fileEncKey, iv, fileNode)

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

// Helper function to create a new FileNode entry in DataStore
// assumes caller is owner of file
func (userdata *User) CreateNewFileNode(filename []byte, fileNameKey []byte, fileEncKey []byte,
	fileMacKey []byte, ownerHash []byte, content []byte, nodeNum int) (fileNodeEntryKey []byte, err error) {

	// Create the content entry in DataStore to point the TextUUID field of the struct to

	// key: HKDF(key = fileNameKey, value = H(filename) || OwnerHash || H("fileNodeContent[num]"))
	// value: Enc(key = fileEncKey, value = contents of file) || HMAC(Enc(key = fileMacKey, value = contents of file))
	nodeNumString := strconv.Itoa(nodeNum)
	// H(filename) || OwnerHash || H("fileNodeContent[num]")
	fileHash := userlib.Hash([]byte(filename))
	fileNodeContentNum := userlib.Hash([]byte("fileNodeContent" + nodeNumString))
	combinedHash := append(fileHash, ownerHash...)
	combinedHash = append(combinedHash, fileNodeContentNum...)
	combinedHash = userlib.Hash(combinedHash)

	contentEntryKey, err := userlib.HashKDF(fileNameKey, combinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return nil, errors.New("Cannot create the content's entry key")
	}

	// Create UUID(contentEntryKey)
	contentEntryUUID, err := uuid.FromBytes((contentEntryKey[len(contentEntryKey)-16:]))
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
	fileNodeNum := userlib.Hash([]byte("fileNode" + nodeNumString))
	newCombinedHash := append(fileHash, ownerHash...)
	newCombinedHash = append(newCombinedHash, fileNodeNum...)
	newCombinedHash = userlib.Hash(newCombinedHash)

	entryKey, err := userlib.HashKDF(fileNameKey, newCombinedHash)
	// Error checking if cannot create the HashKDF
	if err != nil {
		return nil, errors.New("Cannot create the File Node's entry key")
	}

	// Create UUID(entryKey)
	entryUUID, err := uuid.FromBytes((entryKey[len(entryKey)-16:]))
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

// Helper function to retrieve the AuthorizedUser struct after obtaining the AuthorizedUserIntermediate entry
func (userdata *User) GetAuthorizedUser(username string, filename []byte, authorizedUserIntermediate []byte,
	privateKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey) (authorizedUser AuthorizedUser, authorizedUserKey []byte, fileInterKey []byte, err error) {

	// Check integrity and decrypt the retrieved AuthorizedUserIntermediate entry
	decryptedIntermediate, err := userdata.ConfirmAuthenticityIntermediate(filename, authorizedUserIntermediate, privateKey, verifyKey)
	if err != nil {
		return authorizedUser, nil, nil, err
	}

	// Unmarshal the struct and recover information
	var intermediateContent AuthorizedUserIntermediate
	json.Unmarshal(decryptedIntermediate, &intermediateContent)

	// Retrieve fileInterKey, fileEncKey, and fileMacKey
	fileInterKey = intermediateContent.FInter
	ownerHash := intermediateContent.OH
	fileMacKey := intermediateContent.FMac
	fileEncKey := intermediateContent.FEnc

	// Access the AuthorizedUser entry in DataStore
	authorizedUserUUID, authorizedUserKey, err := AccessAuthorizedUser(ownerHash, userdata.Username, fileInterKey)
	if err != nil {
		return authorizedUser, nil, nil, err
	}

	// Decrypt the retrieved AuthorizedUser entry
	decryptedAuthorizedUser, err := userdata.ConfirmAuthenticityHMAC(authorizedUserUUID, fileMacKey, fileEncKey)
	if err != nil {
		return authorizedUser, nil, nil, err
	}

	// Unmarshal the struct and recover information
	var authorizedUserContent AuthorizedUser
	json.Unmarshal(decryptedAuthorizedUser, &authorizedUserContent)

	return authorizedUserContent, authorizedUserKey, fileInterKey, nil
}

// Helper function to retrieve the File struct after obtaining the AuthorizedUserIntermediate entry
func (userdata *User) GetFile(filename []byte, authorizedUserIntermediate []byte,
	privateKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey) (fileContent File,
	fileInterKey []byte, fileEncKey []byte, fileMacKey []byte, fileNameKey []byte, ownerHash []byte, ownerFileAlias []byte, err error) {
	var fileEntryContent File

	// Check integrity and decrypt the retrieved AuthorizedUserIntermediate entry
	decryptedIntermediate, err := userdata.ConfirmAuthenticityIntermediate(filename, authorizedUserIntermediate, privateKey, verifyKey)
	if err != nil {
		return fileEntryContent, nil, nil, nil, nil, nil, nil, err
	}

	// Unmarshal the struct and recover information
	var intermediateContent AuthorizedUserIntermediate
	json.Unmarshal(decryptedIntermediate, &intermediateContent)

	// Retrieve fileInterKey, fileEncKey, and fileMacKey
	fileInterKey = intermediateContent.FInter
	ownerHash = intermediateContent.OH
	fileEncKey = intermediateContent.FEnc
	fileMacKey = intermediateContent.FMac

	userlib.DebugMsg("Assessing an Authorized User for %s. ownerHash: %x, fileInterKey: %x, fileEncKey: %x, fileMacKey: %x", userdata.Username, ownerHash, fileInterKey, fileEncKey, fileMacKey)

	// Access the AuthorizedUser entry in DataStore
	authorizedUserUUID, _, err := AccessAuthorizedUser(ownerHash, userdata.Username, fileInterKey)
	if err != nil {
		return fileEntryContent, nil, nil, nil, nil, nil, nil, err
	}

	// Decrypt the retrieved AuthorizedUser entry
	decryptedAuthorizedUser, err := userdata.ConfirmAuthenticityHMAC(authorizedUserUUID, fileMacKey, fileEncKey)
	if err != nil {
		return fileEntryContent, nil, nil, nil, nil, nil, nil, err
	}

	// Unmarshal the struct and recover information
	var authorizedUserContent AuthorizedUser
	json.Unmarshal(decryptedAuthorizedUser, &authorizedUserContent)

	// Retrieve ownerHash and fileNameKey
	ownerHash = authorizedUserContent.OwnerHash
	fileNameKey = authorizedUserContent.FileNameKey
	ownerFileAlias = authorizedUserContent.OwnerFileAlias

	// Access the File entry in DataStore
	fileUUID, err := userdata.AccessFile(ownerFileAlias, ownerHash, fileNameKey)
	if err != nil {
		return fileEntryContent, nil, nil, nil, nil, nil, nil, err
	}

	// Decrypt the retrieved File entry
	decryptedFile, err := userdata.ConfirmAuthenticityHMAC(fileUUID, fileMacKey, fileEncKey)
	if err != nil {
		return fileEntryContent, nil, nil, nil, nil, nil, nil, err
	}
	// Unmarshal the struct and recover information
	json.Unmarshal(decryptedFile, &fileEntryContent)

	return fileEntryContent, fileInterKey, fileEncKey, fileMacKey, fileNameKey, ownerHash, ownerFileAlias, nil
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
func (userdata *User) StoringNewFile(filename []byte, content []byte, encKey []byte, macKey []byte, nameKey []byte, publicKey userlib.PKEEncKey,
	privateKey userlib.PKEDecKey, signatureKey userlib.DSSignKey, verifyKey userlib.DSVerifyKey) (err error) {
	ownerHash := userlib.RandomBytes(8)
	userlib.DebugMsg("The ownerHash is: %x", ownerHash)
	// Generate fileKey parts
	fileEncKey, fileMacKey, fileNameKey, fileInterKey, err := GenerateFileKeys()
	// Error checking if GenerateFileKeys fails
	if err != nil {
		return errors.New("GenerateFileKeys fails")
	}

	// // Create an InterContent entry in DataStore
	// interContentStruct := InterContent{fileEncKey, fileMacKey}
	// interContentByte, err := json.Marshal(interContentStruct)
	// if err != nil {
	// 	return errors.New("Cannot serialize the InterContent struct")
	// }

	// err = userdata.CreateInterContent(userdata.Username, ownerHash, fileInterKey, fileEncKey, fileMacKey, interContentByte)
	// if err != nil {
	// 	return err
	// }

	// _, interContentKey, err := userdata.AccessInterContent(userdata.Username, ownerHash, fileInterKey)
	// if err != nil {
	// 	return err
	// }
	// Create an AuthorizedUserIntermediate entry in DataStore

	// Create the AuthorizedUserIntermediate struct
	authorizedUserIntermediateStruct := AuthorizedUserIntermediate{fileEncKey, fileMacKey, fileInterKey, ownerHash}
	// Change the AuthorizedUser struct into a byte slice
	authorizedUserIntermediateByte, err := json.Marshal(authorizedUserIntermediateStruct)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the AuthorizedUser struct")
	}

	err = userdata.CreateAuthorizedUserIntermediate(userdata.Username, filename, nameKey, publicKey, fileInterKey, signatureKey, authorizedUserIntermediateByte)
	// Error checking if cannot create an AuthorizedUserIntermediate entry in DataStore
	if err != nil {
		return err
	}

	// Create an AuthorizedUser entry in DataStore
	// Create the OwnerHash = Enc(value = Owner's username, key = enc_key, iv=random)
	// iv := userlib.RandomBytes(16)
	// ownerHash := userlib.SymEnc(encKey, iv, []byte(userdata.Username))

	// Create the AuthorizedUser struct
	authorizedUserStruct := AuthorizedUser{filename, true, ownerHash, fileEncKey, fileMacKey, fileNameKey, fileInterKey, publicKey}
	// Change the AuthorizedUser struct into a byte slice
	authorizedUserByte, err := json.Marshal(authorizedUserStruct)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the AuthorizedUser struct")
	}

	err = userdata.CreateAuthorizedUser(userdata.Username, ownerHash, fileInterKey, fileEncKey, fileMacKey, authorizedUserByte)
	// Error checking if cannot create an AuthorizedUser entry in DataStore
	if err != nil {
		return err
	}

	// Create a FileAccess entry in DataStore
	// Create the FileAccess struct
	authorizedUsers := make([]string, 1)
	authorizedUsers[0] = userdata.Username

	fileAccessStruct := FileAccess{authorizedUsers}
	// Change the File Access struct into a byte slice
	fileAccessByte, err := json.Marshal(fileAccessStruct)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the FileAccess struct")
	}

	err = userdata.CreateFileAccess(userdata.Username, filename, fileInterKey, fileEncKey, fileMacKey, fileAccessByte)
	if err != nil {
		return err
	}

	// Create a FileNode entry in DataStore
	nodeNum := 1
	fileNodeEntry, err := userdata.CreateNewFileNode(filename, fileNameKey, fileEncKey, fileMacKey, ownerHash, content, nodeNum)
	if err != nil {
		return err
	}

	// Create a File entry in DataStore

	// Create the File struct
	fileStruct := File{fileNodeEntry, fileNodeEntry}
	// Change the AuthorizedUser struct into a byte slice
	fileByte, err := json.Marshal(fileStruct)
	// Error checking if json.Marshal fails
	if err != nil {
		return errors.New("Cannot serialize the File struct")
	}

	err = userdata.CreateFile(filename, fileNameKey, fileEncKey, fileMacKey, ownerHash, fileByte)
	if err != nil {
		return err
	}

	return nil
}
