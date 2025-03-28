package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestGetUser1(t *testing.T) {
	clear()
	t.Log("Starting GetUser Test #1")
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "password")
	if err != nil{
		t.Error("Failed initUser(alice) in TestGetUser")
		return
	}


	_, err2 := GetUser("alice", "password")
	// If GetUser returns without hitting err

	if err2 != nil {
		// t.Error says the test fails
		t.Error("Failed to catch corruption of stored UserStruct in DataStore", err2)
		return
	}

}





func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", "alice")



	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.

}

func TestGetUser2(t *testing.T) {
	clear()
	t.Log("Starting GetUser Test #2")
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil{
		t.Error("Failed initUser(alice) in TestGetUser")
		return
	}
	//Re-storing the same UserStruct with the last 64 bytes changed
	h := userlib.RandomBytes(16)
	fraud, _ := uuid.FromBytes(h)
	_, ok := userlib.DatastoreGet(fraud)
	if ok != false {
		t.Error("failed on corrupt user struct")
		return
	}

}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a nonexistent file", err2)
		return
	}
}

func TestSwitchTwoFiles(t *testing.T) {
	d := userlib.DatastoreGetMap()

	ryan, err := InitUser("Ryan", "password")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	skinner, err := InitUser("Skinner", "password")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	ryanFile := []byte("A file")
	ryan.StoreFile("file1", ryanFile)
	skinnerFile := []byte("Another file")
	skinner.StoreFile("file2", skinnerFile)

	keys := make([]uuid.UUID, 0)
	values := make([][]byte, 0)
	for key, value := range d {
		keys = append(keys, key)
		values = append(values, value)
	}

	for i := 0; i < len(keys); i+= 1 {
		userlib.DatastoreSet(keys[len(keys) - i - 1], values[i])
	}

	_, err2 := ryan.LoadFile("file1")
	if err2 == nil {
		t.Error("Downloaded a nonexistent file", err2)
		return
	}

	_, err3 := GetUser("Ryan", "password")
	if err3 == nil {
		t.Error(" a nonexistent file", err2)
		return
	}
}



func TestAppendFile(t *testing.T) {
	clear()
	ryan, err := InitUser("Ryan", "password")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	file := []byte("File.")
	ryan.StoreFile("file3", file)
	update := []byte("Update.")
	ryan.AppendFile("file3", update)
	expected := []byte("File.Update.")
	actual, err := ryan.LoadFile("file3")
	if !reflect.DeepEqual(expected, actual) {
		t.Error("Failed update")
		return
	}
}



func TestCorruptFile(t *testing.T) {
	d := userlib.DatastoreGetMap()
	ryan, err := InitUser("Ryan", "password")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	uncorrupt := []byte("uncorrupted file")
	ryan.StoreFile("uncorrupt", uncorrupt)

	for key, val := range d {
		userlib.DatastoreSet(key, val[:len(val)/2])

	}
	_, err1 := ryan.LoadFile("uncorrupt")
	if  err1 == nil {
		t.Error("Stored data is corrupted.")
		return
	}
	_, err2 := GetUser("Ryan", "password")
	if  err2 == nil {
		t.Error("Stored data is corrupted.")
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v3 := []byte("This is a test")
	u.StoreFile("file1", v3)

	var v2 []byte
	var magic_string string

	v, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	if !(reflect.DeepEqual(v, v3)) {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
	update := []byte(" This is an update.")
	newFile := []byte("This is a test This is an update.")
	err = u.AppendFile("file1", update)
	if err != nil {
		t.Error("Failure in appending file", err)
	}

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}

	if !reflect.DeepEqual(v, newFile) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	if !reflect.DeepEqual(v2, newFile) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}


func TestThree(t *testing.T) {
	beans, err2 := InitUser("beans", "password")
	if err2 != nil {
		t.Error("Failed to download the file after sharing", err2)
		return
	}
	alice, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	bob, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	v2, err := bob.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if err2 != nil {
		t.Error("Failed to initialize beans", err2)
		return
	}
	magic_string, err := alice.ShareFile("file1", "beans")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = beans.ReceiveFile("beansfile", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	beansfile, err := beans.LoadFile("beansfile")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	actual, err := alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file after sharing", err)
		return
	}
	if !reflect.DeepEqual(beansfile, actual) {
		t.Error("Shared file is not the same", actual)
		return
	}
	if !reflect.DeepEqual(beansfile, v2) {
		t.Error("Shared file is not the same", v2)
		return
	}
}

func TestThreeWaysShareEdit(t *testing.T) {
	beans, _ := GetUser("beans", "password")
	u2, err2 := GetUser("bob", "foobar")
	u, err2 := GetUser("alice", "fubar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	change := []byte(" Some beans")
	beansfile, err := beans.LoadFile("beansfile")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	updatedFile := append(beansfile, change...)
	err = beans.AppendFile("beansfile", change)
	beansUpdate, err := beans.LoadFile("beansfile")
	if err != nil {
		t.Error("Failed to load file with sharing", err)
		return
	}
	uUpdate, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Alice failed to load with sharing", err)
		return
	}
	bobUpdate, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("bob failed to load with sharing", err)
		return
	}
	if !reflect.DeepEqual(beansUpdate, uUpdate) || !reflect.DeepEqual(beansUpdate, bobUpdate) || !reflect.DeepEqual(beansUpdate, updatedFile){
		t.Error("Should be equal", updatedFile, uUpdate, bobUpdate)
		return
	}
}

func TestThreeWaysShare(t *testing.T) {
	beans, _ := GetUser("beans", "password")
	alice, err2 := GetUser("alice", "fubar")
	if err2 != nil {
		t.Error("Failed to initialize josh", err2)
		return
	}
	bob, err3 := GetUser("bob", "foobar")
	if err3 != nil {
		t.Error("Failed to initialize josh", err2)
		return
	}
	josh, err2 := InitUser("josh", "joshua")
	if err2 != nil {
		t.Error("Failed to initialize josh", err2)
		return
	}
	magic_string, err := beans.ShareFile("beansfile", "josh")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = josh.ReceiveFile("more", "beans", magic_string)
	if err != nil {
		t.Error("Failed to receive message", err)
		return
	}
	beansfile, err := beans.LoadFile("beansfile")
	if err != nil {
		t.Error("beans unable to load", err)
		return
	}
	actual, err := josh.LoadFile("more")
	if err != nil {
		t.Error("josh unable to load", err)
		return
	}

	if !reflect.DeepEqual(beansfile, actual) {
		t.Error("Should be equal", actual, beansfile)
		return
	}
	change2 := []byte(" LeafNodeUpdate")
	updatedFile := append(beansfile, change2...)

	err = josh.AppendFile("more", change2)


	joshUpdate, err := josh.LoadFile("more")
	if err != nil {
		t.Error("Failed to load file with sharing", err)
		return
	}
	beansUpdate, err := beans.LoadFile("beansfile")
	if err != nil {
		t.Error("Failed to load file with sharing", err)
		return
	}
	bobUpdate, err := bob.LoadFile("file2")
	if err != nil {
		t.Error("Failed to load file with sharing", err)
		return
	}
	aliceUpdate, err := alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file with sharing", err)
		return
	}
	if !reflect.DeepEqual(joshUpdate, updatedFile) || !reflect.DeepEqual(beansUpdate, updatedFile) ||
		!reflect.DeepEqual(bobUpdate, updatedFile) || !reflect.DeepEqual(aliceUpdate, updatedFile) {
		t.Error("File appened did not save info up tree")
		return
	}

}

func TestRevokes(t *testing.T) {
	u, err2 := GetUser("alice", "fubar")
	if err2 != nil {
		t.Error("Failed to initialize User", err2)
		return
	}
	beans, err2:= GetUser("beans", "password")
	if err2 != nil {
		t.Error("Failed to initialize User", err2)
		return
	}
	bob, err3 := GetUser("bob", "foobar")
	if err3 != nil {
		t.Error("Failed to initialize User", err3)
		return
	}
	josh, err2 := GetUser("josh", "joshua")
	if err2 != nil {
		t.Error("Failed to initialize josh", err2)
		return
	}

	// Remove file permission for beans
	err := u.RevokeFile("file1", "beans")
	if err != nil {
		t.Error("Error revoking file", err)
		return
	}
	/// check that ALice has access
	_, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Origin User doesn't have access", err)
		return
	}
	// Check beans & Josh dont have access
	_, err = beans.LoadFile("beansfile")
	if err == nil {
		t.Error("Beans Shouldnt have access")
		return
	}
	_, err = josh.LoadFile("more")
	if err == nil {
		t.Error("Josh shouldnt have access")
		return
	}
	// Check that Bob has access
	_, err = bob.LoadFile("file2")
	if err != nil {
		t.Error("Bob should have access")
		return
	}

}

