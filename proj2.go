package proj2

// CS 161 Project 2 Fall 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (

	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"


	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	"strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	Userbytes []byte
	Password []byte
	RSAdecr userlib.PKEDecKey
	RSAsign userlib.DSSignKey
	//Unique Identifier for USer Struct Decr/Encr
	UUID    userlib.UUID
	// User struct Encr & Decr Keys:
	HMACKey []byte
	SymmetricKey []byte
	FileMap map[string]userlib.UUID
	KeyMap map[string][][]byte


}

type Node struct {
	User string
	Shared []uuid.UUID
	KeyMap map[uuid.UUID][][]byte
	SharedRecordUUID uuid.UUID
}


type Updates struct {
	UpdateUUID map[int]uuid.UUID
	Keys map[int][][]byte
}

// Userupdate is used to take in a given user, jsonmarshall and encrypt w/ hmpac
// Calls DatastoreSet on updated user
func (userdata *User) UserUpdate() {
	var err error

	// 2b) Geneerate summetric keys
	// CHeck if symmetric Keys for user struct already exist
	if userdata.SymmetricKey == nil || userdata.HMACKey == nil {
		Masterkey := userlib.Argon2Key(userdata.Password, userdata.Userbytes, 32 )
		//Generate deterministic symmetric and HMAC Keys
		userdata.SymmetricKey = Masterkey[:16]
		userdata.HMACKey = Masterkey[16:]
	}


	//3) JSON & encrypt user struct, then send into DataStore
	userJson, err := json.Marshal(userdata)
	if err != nil {

		return
	}
	userStore, err := verifiedEncrypt(userdata.SymmetricKey, userdata.HMACKey, userJson)
	userlib.DatastoreSet(userdata.UUID, userStore)

}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func GetUUIDHelper(username string, password string)(result uuid.UUID){
	key := userlib.Argon2Key([]byte(password), []byte(username + "3"), 16)
	result, err :=uuid.FromBytes(key[:16])
	if err != nil {
		return uuid.Nil
	}
	return result

}


func InitUser(username string, password string) (userdataptr *User, err error) {
	// 1) Initialize user struct & pointer to userstruct
	var userdata User
	userdataptr = &userdata
	userdata.Username = username
	userdata.Password = []byte(password)
	// 2) Generate User data to:  a) store encrypted User Struct in Datastore
			//b) Decrypt and retrieve user data from User Struct
		// NOTE: User username + password + deterministic salt to generate the 3 keys
	//2a) generate UUID from username and password (DataStore Key for user Struct):
	userdata.Userbytes = []byte(userdata.Username)


	userdata.UUID = GetUUIDHelper(username, password)

	// Create and store symmetric RSA keys
	RSAsign, RSAver, _ := userlib.DSKeyGen()
	RSAencr,  RSAdecr, _ := userlib.PKEKeyGen()

	userdata.RSAdecr = RSAdecr
	userdata.RSAsign = RSAsign

	encrKeyString := "RSAencr" + username
	verKeyString := "RSAver" + username

	userlib.KeystoreSet(encrKeyString, RSAencr)
	userlib.KeystoreSet(verKeyString, RSAver)


	// CALL HELPER FUNC
	userdata.UserUpdate()


	return userdataptr, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	userdata.Username = username
	userdata.Password = []byte(password)

	//Get UUID for User
	userdata.Userbytes = []byte(username)


	userUUID := GetUUIDHelper(username, password)


	//Evaluate HMAC for Stored & generated UserStruct
	storedStruct, ok := userlib.DatastoreGet(userUUID)
	if ok == false {
		userlib.DebugMsg("Couldn't get encr userstruct with given uuid")

	}
	//Generate deterministic symmetric and HMAC Keys
	Masterkey := userlib.Argon2Key(userdata.Password, userdata.Userbytes, 32 )
	symmetricKey := Masterkey[:16]
	HMACKey := Masterkey[16:]


	userDataDecr, err := verifiedDecrypt(symmetricKey, HMACKey, storedStruct)
	if err !=nil {
		return nil, errors.New("Stored user is corrupted")
	}
	var userUnmarsh User
	err = json.Unmarshal(userDataDecr, &userUnmarsh)
	if err != nil {

		userlib.DebugMsg("Couldnt generate userdata from datastore")
	}

	return &userUnmarsh, nil
}

func verifiedEncrypt(encrKey []byte, signKey []byte, data []byte) ([]byte, error){
	iv := userlib.RandomBytes(userlib.AESKeySize)
	blockSize := userlib.AESBlockSize
	var buffsize int
	if len(data) % blockSize != 0 {
		if blockSize - len(data) > 0 {
			buffsize = blockSize- len(data)
		} else {
			buffsize = 16- (len(data) % blockSize)
		}
	}

	buff := make([]byte, buffsize)
	data = append(data, buff...)
	encryptedData := userlib.SymEnc(encrKey, iv, data)

	signed, err := userlib.HMACEval(signKey, encryptedData)

	if err != nil {
		return nil, err
	}

	finalData := append(encryptedData, signed...)
	return finalData, nil
}

func decryptHelper(rawData []byte) ([]byte){
	var counter int
	counter = 0
	for i := len(rawData)-1; i >0; i-- {
		if rawData[i] == 0 {
			counter +=1

		} else {
			return rawData[:len(rawData)-counter]
		}
	}
	return rawData[:len(rawData)-counter]
}

func verifiedDecrypt(decrKey []byte, verifKey []byte, rawData []byte) ([]byte, error) {
	if len(rawData) - userlib.HashSize <0 {
		return nil, errors.New("Corrupted MAC")
	}
	MAC := rawData[len(rawData) - userlib.HashSize:]
	data := rawData[:len(rawData) - userlib.HashSize]

	//Check for integrity
	userHash, err := userlib.HMACEval(verifKey, data)

	if err != nil {
		return nil, err
	}

	if !(userlib.HMACEqual(userHash, MAC)) {
		return nil, errors.New("HMAC verification failed")
	}


	decryptedData := userlib.SymDec(decrKey, data)
	finalDecryptedData := decryptHelper(decryptedData)

	return finalDecryptedData, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	var err error
	// 1) Create fileUUID & Symmetric public keys for file storage
	fileUUID := uuid.New()
	encKey := userlib.RandomBytes(userlib.AESKeySize)
	signKey := userlib.RandomBytes(16)

	// Store keys for file retrieval
	if userdata.KeyMap == nil {
		userdata.KeyMap = make(map[string][][]byte)
	}
	userdata.KeyMap[filename] = [][]byte{encKey,signKey}
	// Store file UUID for file retrieval
	if userdata.FileMap == nil {
		userdata.FileMap = make(map[string]userlib.UUID)
	}
	userdata.FileMap[filename] = fileUUID

	nodeUUID := uuid.New()
	userdata.FileMap[filename + "_shareNode"] = nodeUUID
	newNode := Node{userdata.Username, make([]uuid.UUID, 0), nil,uuid.Nil}
	shareEncrKey := userlib.RandomBytes(userlib.AESKeySize)
	shareSignKey := userlib.RandomBytes(16)
	userdata.KeyMap[filename + "_shareNode"] = [][]byte{shareEncrKey,shareSignKey}

	jsonShared, err := json.Marshal(newNode)
	if err != nil {
		return
	}
	encrNode, err := verifiedEncrypt(shareEncrKey,shareSignKey, jsonShared)
	if err != nil {
		return
	}
	userlib.DatastoreSet(nodeUUID, encrNode)


	// 2) Marshall, encrypt, & sign fileData, THEN store in datastore under UUID
	packaged_data, err := json.Marshal(data)
	encrData, err := verifiedEncrypt(encKey, signKey,packaged_data)

	if err != nil {
		return
	}

	userlib.DatastoreSet(fileUUID, encrData)

	//3) check for updates & if Empty create Updates UUID & stymmetric key
	// along with updates struct so it doesn't have to be made later
	_, ok := userdata.FileMap[filename + "numAppends"]
	if ok == false {
		appendsUUID := uuid.New()
		appendsEncKey := userlib.RandomBytes(userlib.AESKeySize)
		appendsSignKey := userlib.RandomBytes(16)

		userdata.FileMap[filename + "numAppends"] = appendsUUID
		userdata.KeyMap[filename + "numAppends"] = [][]byte{appendsEncKey, appendsSignKey}

		updateFile := Updates{UpdateUUID: make(map[int]uuid.UUID), Keys: make(map[int][][]byte)}
		updateJSON, err := json.Marshal(updateFile)
		if err != nil {
			return
		}

		encryptedUpdates, err := verifiedEncrypt(appendsEncKey, appendsSignKey, updateJSON)

		if err != nil {
			return
		}

		userlib.DatastoreSet(appendsUUID, encryptedUpdates)
	}
	// userData UPDATED: REENCRYPT AND RE-STORE USER STRUCT
	userdata.UserUpdate()

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	if userdata == nil{
		return  errors.New("No such user existts")
	}
	//1) Get fileUUID & updatesUUID to pull from datastore
	fileUUID, ok := userdata.FileMap[filename]
	if !ok || fileUUID == uuid.Nil {
		return errors.New("file not found for user!")
	}

	appendsUUID, ok := userdata.FileMap[filename + "numAppends"]
	if !ok || appendsUUID == uuid.Nil {
		return errors.New("updates struct not found for user!")
	}

	//Get the updates node

	//2) Get updates struct encr & decr Keys from keymap

	dk := userdata.KeyMap[filename + "numAppends"][0]
	vk := userdata.KeyMap[filename + "numAppends"][1]
	//3) Decrypt updates struct

	updates, updatesUUID, dk, vk, err := userdata.UpdatesHelper(appendsUUID, dk, vk)
	if err != nil {
		return err
	}
	// 4) Create new file encr& verif keys along with UUID for new Numappends, and store in USER file&KeyMaps
	numAppends := len(updates.UpdateUUID)
	numAppendsUUID := uuid.New()
	appendEncrKey := userlib.RandomBytes(userlib.AESKeySize)
	appendSignKey := userlib.RandomBytes(16)
	if userdata.FileMap == nil {
		userdata.FileMap= make(map[string]uuid.UUID)
	}
	userdata.FileMap[filename + "numAppends" + strconv.Itoa(numAppends)] = numAppendsUUID

	if userdata.KeyMap == nil {
		userdata.KeyMap = make(map[string][][]byte)
	}
	userdata.KeyMap[filename + "numAppends" + strconv.Itoa(numAppends)] = [][]byte{appendEncrKey,appendSignKey}

	// 5)JSON, Encrypt, Sign, and store new Filedata in Datasotre
	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}
	encrAppendsData, err2 := verifiedEncrypt(appendEncrKey, appendSignKey, jsonData)
	if err2 != nil {
		return err
	}
	userlib.DatastoreSet(numAppendsUUID, encrAppendsData)
	userdata.UserUpdate()

	// 6) Update Updates map
	updates.UpdateUUID[numAppends] = numAppendsUUID
	updates.Keys[numAppends] = [][]byte{appendEncrKey, appendSignKey}

	//7) encrypt and, json, and store Updates in datastore
	jsonReUpdates, err := json.Marshal(updates)
	if err != nil {
		return err
	}

	reEncrUpdates, err := verifiedEncrypt(dk, vk, jsonReUpdates)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(updatesUUID, reEncrUpdates)

	return
}

func (userdata *User) LoadHelper(UUID uuid.UUID, decrKey []byte, verKey []byte) (data []byte, err error){
	fileEncrypted, ok := userlib.DatastoreGet(UUID)
	if !ok || fileEncrypted == nil {
		return nil, errors.New("data store doesn't have this file")
	}
	decFile, err := verifiedDecrypt(decrKey, verKey, fileEncrypted)
	if err != nil {
		return nil, err
	}
	var shared Shared
	err = json.Unmarshal(decFile, &shared)

	if err != nil {
		var fileData []byte
		err = json.Unmarshal(decFile, &fileData)
		if err != nil {
			return nil, err
		}
		return fileData, err
	}

	return userdata.LoadHelper(shared.FileUUID, shared.FileDecrKey, shared.FileVerKey)
}

// Updates helper assists in updating UUIDs and symmetric keys for updating updates struct
func (userdata *User) UpdatesHelper(UUID uuid.UUID, decrKey []byte, verKey []byte) (updates *Updates, resultID uuid.UUID, dk []byte, vk []byte, err error){
	fileEncrypted, ok := userlib.DatastoreGet(UUID)
	if !ok || fileEncrypted == nil {
		return nil, uuid.Nil, nil, nil, errors.New("data store doesn't have this file")
	}
	decFile, err := verifiedDecrypt(decrKey, verKey, fileEncrypted)
	if err != nil {
		return nil,uuid.Nil, nil, nil, err
	}

	var share Shared
	err = json.Unmarshal(decFile, &share)
	if err != nil || share.FileUUID == uuid.Nil {
		var update Updates
		err = json.Unmarshal(decFile, &update)

		if err == nil{
			return &update, UUID, decrKey, verKey, nil
		}
		return nil, uuid.Nil, nil, nil, err
	}

	return userdata.UpdatesHelper(share.AppendsUUID, share.AppendsEncr, share.AppendsVerif)

}
// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// Get file UUID
	if userdata == nil{
		return nil, errors.New("No such user exists")
	}
	if userdata.FileMap == nil {
		return nil, errors.New("no files for this user")
	}
	fileUUID, ok := userdata.FileMap[filename]
	if !ok || fileUUID == uuid.Nil {
		return nil, errors.New("no such file for user")
	}

	// Get stored data
	storeFileData, ok := userlib.DatastoreGet(fileUUID)
	if ok ==false || storeFileData == nil{
		return nil, errors.New(strings.ToTitle("File for given FileName is not stored in datastore"))
	}

	// Get keys for decrypting and verifying
	if  userdata.FileMap == nil {
		return nil, errors.New("No keys for given Filename")
	}
	decrKey := userdata.KeyMap[filename][0]
	verifKey := userdata.KeyMap[filename][1]

	rawData, err := userdata.LoadHelper(fileUUID,decrKey,verifKey)
	if err != nil || rawData == nil{
		return nil, err
	}

	// 2a) Get UUID & Keys for update struct
	updatesUUID, ok := userdata.FileMap[filename + "numAppends"]
	if ok {
		updatesDecr := userdata.KeyMap[filename+"numAppends"][0]
		updatesVer := userdata.KeyMap[filename+"numAppends"][1]

		//2b) decrypt & unmarshall updates struct


		updates,_, _, _, err := userdata.UpdatesHelper(updatesUUID, updatesDecr, updatesVer)
		if err != nil{
			return nil, errors.New("couldn't find root updates struct!")
		}
		numAppends := len(updates.UpdateUUID)
		if numAppends > 0 {
			for i := 0; i < numAppends; i+=1 {
				//1) Compute UUID for each append
				ithUUID := updates.UpdateUUID[i]
				//2) Pull appended data from datastore
				encrAppend, ok := userlib.DatastoreGet(ithUUID)
				if ok == false {
					userlib.DebugMsg("failed to load appendedFileData from DataStore")
				}
				// Decrypt appended data
				decrKey := updates.Keys[i][0]
				verifKey := updates.Keys[i][1]

				appendData, err := verifiedDecrypt(decrKey, verifKey, encrAppend)
				if err != nil {
					userlib.DebugMsg("could not decrypt encrypted file from DataStore")
				}
				var holder []byte
				err = json.Unmarshal(appendData, &holder)
				if err != nil {
					return nil, err
				}

				rawData = append(rawData, holder...)
			}
		} else {
			userlib.DebugMsg("No appends found for FileName!")
		}
	}
	return rawData, nil
}

type Shared struct {

	FileUUID userlib.UUID
	FileDecrKey []byte
	FileVerKey []byte
	AppendsUUID userlib.UUID
	AppendsEncr []byte
	AppendsVerif []byte
	TreeNodeUUID uuid.UUID
	TreeNodeEncr []byte
	TreeNodeSign []byte

}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (magic_string string, err error) {
	fileUUID, ok := userdata.FileMap[filename]
	if !ok || fileUUID == uuid.Nil {
		return "", errors.New("no such file for user")
	}

	nodeUUID := userdata.FileMap[filename + "_shareNode"]

	// get shared keys
	decrNode := userdata.KeyMap[filename + "_shareNode"][0]
	verNode := userdata.KeyMap[filename + "_shareNode"][1]
	// get shared node from datastore

	encrSharedNode, ok := userlib.DatastoreGet(nodeUUID)
	if !ok{
		return
	}
	jsonNode, err := verifiedDecrypt(decrNode, verNode, encrSharedNode)
	if err != nil{
		return
	}
	var rawSharedNode Node
	err = json.Unmarshal(jsonNode, &rawSharedNode)
	if err != nil{
		return
	}

	newNodeUUID := uuid.New()
	rawSharedNode.Shared = append(rawSharedNode.Shared, newNodeUUID)
	if rawSharedNode.KeyMap == nil{
		rawSharedNode.KeyMap = make(map[uuid.UUID][][]byte, 0)
	}

	sharedUUIDbytes := userlib.RandomBytes(16)
	sharedEncrKey := userlib.RandomBytes(userlib.AESKeySize)
	sharedVerifKey:= userlib.RandomBytes(userlib.AESKeySize)
	magicString := append(append([]byte(sharedUUIDbytes), sharedEncrKey...), sharedVerifKey...)
	sharedUUID, err := uuid.FromBytes(sharedUUIDbytes)
	if err != nil{
		return "humez", err
	}
	bobNode := Node{recipient, make([]uuid.UUID, 0),nil, sharedUUID}
	bobEncr := userlib.RandomBytes(userlib.AESKeySize)
	bobSign := userlib.RandomBytes(16)


	rawSharedNode.KeyMap[newNodeUUID] = [][]byte{bobEncr, bobSign}

	jsonShared, err := json.Marshal(rawSharedNode)
	if err != nil {
		return
	}
	encrNode, err := verifiedEncrypt(decrNode, verNode, jsonShared)
	if err != nil {
		return
	}
	userlib.DatastoreSet(nodeUUID, encrNode)

	jsonBob, err := json.Marshal(bobNode)
	if err != nil {
		return
	}
	encrBob, err := verifiedEncrypt(bobEncr, bobSign, jsonBob)
	if err != nil {
		return
	}

	userlib.DatastoreSet(newNodeUUID, encrBob)

	fileDecrKey := userdata.KeyMap[filename][0]
	fileVerKey := userdata.KeyMap[filename][1]

	sharedStruct := Shared{
		FileUUID: fileUUID,
		FileDecrKey: fileDecrKey,
		FileVerKey: fileVerKey,
		AppendsUUID: userdata.FileMap[filename + "numAppends"],
		AppendsEncr: userdata.KeyMap[filename + "numAppends"][0],
		AppendsVerif: userdata.KeyMap[filename + "numAppends"][1],
		TreeNodeUUID: newNodeUUID,
		TreeNodeEncr: bobEncr,
		TreeNodeSign: bobSign,
	}
	// Store sharedStruct on datastore

	sharedJson, err:= json.Marshal(sharedStruct)
	if err != nil {
		return "", err
	}

	encrStruct, err := verifiedEncrypt(sharedEncrKey, sharedVerifKey, sharedJson)
	if err != nil {
		return "", err
	}


	sharedUUID, err =  uuid.FromBytes(sharedUUIDbytes)
	if err != nil {
		return "", err
	}

	userlib.DatastoreSet(sharedUUID, encrStruct)

	encrKeyString := "RSAencr" + recipient
	recipientRSAencr, _ := userlib.KeystoreGet(encrKeyString)
	// Encrypt and sign magic word
	encrMagicString, err := userlib.PKEEnc(recipientRSAencr, magicString)
	if err != nil {
		return "", err
	}

	magicStringSig, err := userlib.DSSign(userdata.RSAsign, encrMagicString)
	if err != nil {
		return "", err
	}

	return string(append(encrMagicString, magicStringSig...)), nil

}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) error {

	//1) Receive magic string, then verify and Decrypt it
	// Convert magic string to byte array then slit into RSA encr and vverif for struct
	magic_bytes := []byte(magic_string)
	// Recipient (user) verifies SendStruct with sender's public key

	verKeyString := "RSAver" + sender
	senderRSAver, ok := userlib.KeystoreGet(verKeyString)
	if !ok {
		return errors.New("Invalid key from keystore!")
	}
	if len(magic_bytes)/2 != 256 {
		return errors.New("Magic String has been currupted!")
	}
	err := userlib.DSVerify(senderRSAver, magic_bytes[:len(magic_bytes)-256], magic_bytes[len(magic_bytes) -256:])
	if err != nil {
		return errors.New("could not verify magic string")
	}
	// decrypts with User's Private key
	decrMagic, err := userlib.PKEDec(userdata.RSAdecr, magic_bytes[:len(magic_bytes) - 256])
	if err != nil {
		return errors.New("Could not decrypt magic string")
	}
	sharedUUID, err := uuid.FromBytes(decrMagic[:16])
	if err != nil {
		return errors.New("shared struct UUID corrupted")
	}
	sharedDecrkey := decrMagic[16:32]
	sharedVerKey := decrMagic[32:]
	// store Decr & Verif keys for decrypting stored struct
	/// Get shared struct from datastore, decrypt with sharedKeys, & json.unmarshall into sharedstruct
	encrStruct, ok := userlib.DatastoreGet(sharedUUID)
	if !ok || encrStruct == nil {
		return errors.New("couldn't get shared struct from datastore")
	}
	decrStruct, err := verifiedDecrypt(sharedDecrkey,sharedVerKey, encrStruct)
	if err != nil {
		return err
	}
	var shared Shared
	err = json.Unmarshal(decrStruct, &shared)
	if err != nil {
		return err
	}
	if userdata.KeyMap == nil {
		userdata.KeyMap = make(map[string][][]byte)
	}
	userdata.KeyMap[filename] = [][]byte{sharedDecrkey, sharedVerKey}
	userdata.KeyMap[filename + "numAppends"] = [][]byte{sharedDecrkey, sharedVerKey}
	userdata.KeyMap[filename + "_shareNode"] = [][]byte{shared.TreeNodeEncr, shared.TreeNodeSign}

	// get shared keys
	if userdata.FileMap == nil {
		userdata.FileMap = make(map[string]userlib.UUID)
	}
	userdata.FileMap[filename] = sharedUUID
	userdata.FileMap[filename + "numAppends"] = sharedUUID
	userdata.FileMap[filename + "_shareNode"] = shared.TreeNodeUUID

	// End of helper funct: STORE user Struct for initUser
	userdata.UserUpdate()


	return nil
}

func (userdata *User) RevokeHelper(target string, UUID uuid.UUID, decrKey []byte, verKey []byte)(sharedUUID uuid.UUID, err error, ok bool){
	fileEncrypted, ok := userlib.DatastoreGet(UUID)
	if !ok || fileEncrypted == nil {
		return  uuid.Nil, errors.New("data store doesn't have this file"), false
	}
	decFile, err := verifiedDecrypt(decrKey, verKey, fileEncrypted)
	if err != nil {
		return uuid.Nil, err, false
	}
	var node Node
	err = json.Unmarshal(decFile, &node)

	if err != nil {
		return uuid.Nil, err, false
	}
	if node.User == target {
		return node.SharedRecordUUID, nil, true
	}
	for i := 0; i < len(node.Shared); i++{
		thisUUID := node.Shared[i]
		decrKey := node.KeyMap[thisUUID][0]
		verKey := node.KeyMap[thisUUID][1]
		newuuid, err, ok := userdata.RevokeHelper(target, node.Shared[i], decrKey, verKey)
		if err != nil {
			return uuid.Nil, err, false
		}
		if ok {
			return newuuid, nil, true
		}
	}

	return uuid.Nil, nil, false

}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	_, err = userdata.LoadFile(filename)
	if err != nil {
		return errors.New("Trying to remove a file that doesn't exist!!")
	}
	node := userdata.FileMap[filename + "_shareNode"]
	dk := userdata.KeyMap[filename + "_shareNode"][0]
	vk := userdata.KeyMap[filename + "_shareNode"][1]
	targetUUID, err, ok := userdata.RevokeHelper(target_username, node, dk, vk)
	if err != nil || !ok {
		return errors.New("File is not shared with this user!")
	}
	userlib.DatastoreDelete(targetUUID)

	return
}
