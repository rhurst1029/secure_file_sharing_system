# Project 2 Design Doc

**Ryan Hurst**  
**3032757769**

---

## Section 1: System Design

### 1. How is a file stored on the server?

The client starts by creating a new random UUID, along with random 
symmetric keys for storing and retrieving the encrypted file. Next, the 
client initializes `KeyMap` and `FileMap`, mapping the given `filename` 
to the generated encryption and signature keys, and the given `filename` 
to the randomly generated UUID, respectively.

`KeyMap` and `FileMap` will later be used for mapping the filename to 
symmetric keys along with UUIDs for new updates from any user with access 
to the file.

After initializing and filling `FileMap` and `KeyMap`, the client 
`json.Marshals` the raw data for the given filename, encrypts and signs 
the bytes generated, and stores the encrypted data in `DataStore` under 
the random UUID generated for the filename.

To initialize the structure for sharing files with other users, we check 
that the given file doesn’t contain any updates, then proceed by creating 
an `appendsUUID`, along with random encryption and signature keys for 
encrypting and storing file updates.

We then create an `appendsUUID` and keys for updates, storing them in 
`FileMap` and `Keymap` under `filename + "numappends"` so we can update 
any file changes for any user with access to the file.

For later sharing functionality, we initialize an empty `Node` struct, 
which creates a shared tree structure by storing the UUID of the `Shared` 
struct (covered in (2)). Finally, the client updates, encrypts, and 
stores the updated `User` Struct in `DataStore` under the given user's 
UUID.

---

### 2. How does a file get shared with another user?

The client first checks that there is a `fileUUID` for the given 
filename. To allow for proper sharing and revocation functionality, the 
client receives the UUID for the sharing `Node` from the `FileMap` and 
`KeyMap`, decrypts, and generates the necessary symmetric keys & UUID for 
the recipient, which gives the recipient access to the `Shared` struct.

After encrypting and storing the new `Node` on `DataStore` for proper 
file sharing & revocation, the client then creates a `Shared` struct that 
holds the symmetric keys & UUIDs for the file, updates to the file, and 
any Nodes the recipient may use for later sharing.

The client then generates a `magicString` containing `Shared` struct UUID 
& symmetric keys. To send the information needed to receive the 
`sharedStruct`, the client encrypts the `magicString` with the 
Recipient’s RSA public encryption key, and signs with the Sender’s RSA 
Private Signature key.

The encrypted magic string and its RSA signature are appended and sent as 
a string over the insecure channel to the recipient.

To receive a file, the recipient verifies the signature on the magic 
string with the Sender’s Public RSA verification key to ensure integrity 
and authenticity. Once verified, the recipient then decrypts the magic 
string with the recipient’s RSA private decryption key, receiving a byte 
array with the UUID, decryption, and verification keys to receive the 
`sharedStruct` from `DataStore`.

After receiving and decrypting the shared struct with the keys obtained 
in the `magicString`, the user initializes and stores the UUIDs & keys 
for the given `filename` by traversing the tree of `Node` structs.

---

### 3. What is the process of revoking a user’s access to a file?

The client first ensures that the requested `filename` to revoke exists 
for the given user, then saves the original file plus all of the appended 
data if the given file exists by calling `LoadFile` on `filename`.

Next, the client receives the UUIDs for the root file `Node` 
(`FileMap[filename + "_shareNode"]`) and its updates, which gives us 
access to the Users in the shared tree structure.

To remove all access to the file for the given user, the client then 
traverses from the root `Node`, decrypting and checking for the target 
user’s `Node`.

Once the target user’s `Node` is found, the client removes the `Node` 
from `Datastore`. This removes access to the target user, along with 
anyone that the target user has shared with, *without* removing file 
access for anyone else.

---

### 4. How does your design support efficient file append?

To support efficient file appends, I split the storage of file data for 
the original file from the storage of appended data in `DataStore`. This 
allows us to decrease runtime demand by only requiring the encryption and 
storage of the *new* appended data.

**Append process:**

- Get the fileUUID (`FileMap[filename]`) and the UUID for Updates struct 
from the User’s `FileMap` (`FileMap[filename + "numAppends"]`).
- Get the encrypted User Struct stored in `DataStore` under the UUID for 
the updates struct.
- Get the decryption & verification keys for the Updates struct from the 
User’s `KeyMap` (`KeyMap[filename + "numAppends"]`).
- Decrypt the Updates struct and get the number of appends made to the 
file via the length of `appendUUIDs` stored.
- Generate a new UUID and keys for the next append.
- Store UUID and keys under `FileMap` and `KeyMap`.
- `json.Marshal`, encrypt, and sign the appended data; store it in 
`DataStore` under the append UUID.
- Update the User struct.
- Update the Updates struct:
  - Add append UUID: `updates.UpdateUUID[numAppend]`
  - Add keys: `updates.Keys[numAppend]`
- Marshal, encrypt, and sign the Updates struct and store it under its 
UUID in `DataStore`.

---

## Section 2: Security Analysis

### 1. Man in the Middle

To demonstrate the Integrity and Confidentiality of our system, we 
introduce an active eavesdropper, Eve, who listens in on Alice sharing a 
file to Bob.

If Eve intercepts the magic string with the intent to:
- (a) tamper with the file sent to Bob, or
- (b) send Bob a different magic string to a malicious file,

our system defends against this by requiring Eve to verify the signature 
and decrypt the magic string with Bob’s private RSA key — which she can't 
do.

---

### 2. DataStore Vulnerability

Since the `DataStore` is untrusted, we assume Eve has access to its 
files. Eve could try to swap files so that when the user loads a file, 
it’s replaced with a malicious one.

However, all file data is encrypted using generated encryption keys, and 
the decryption key is stored in the **trusted** server KeyStore. Any 
signature mismatch between Eve’s tampered file and the `User`’s `KeyMap` 
will throw an error upon loading.

---

### 3. File Revocation

Eve has been listening and saving information shared between Bob and 
Alice. If Bob revokes Alice’s access, Eve might try to use past data to 
regain access.

The system prevents this by:
- Encrypting and signing the `User` struct before storing it.
- Encrypting the sharing struct, making previously collected information 
useless.

---
"""# 
secure_file_sharing_system
