#ifndef VAULT_HPP
#define VAULT_HPP

#include <vector>
#include <string>
#include <sodium.h>
/*______________________________________________________________________________
Vault Class:
 - Setting the master password. 
 - Salting and hashing passwords. 
 - Adding, and deleting credentials.
 - Storing credintials in a encypted file.
 - Verifying the master password
______________________________________________________________________________*/
/*______________________________________________________________________________
Struct for credintials
______________________________________________________________________________*/
struct Credential 
{
    std::string site;
    std::string username;
    unsigned char* password {};
    size_t passwordLength {};
};

class Vault
{
private:
    const size_t saltLength {16};       // 16 bytes for the salt.
    unsigned char* salt {};             // Generated with libsodium
    unsigned char* masterPassword {};   // User input for masterPassword
    size_t masterPasswordLength {};     // track length for freeing
    unsigned char* masterKey {};        // key derived from password & salt
    size_t masterKeyLength {};          // Track Length for freeing

    //struct Credential;                      // Website/username/password
    std::vector<Credential> credentials;

    unsigned char markerNonce[crypto_secretbox_NONCEBYTES];
    std::vector<unsigned char> markerCipher;

public:
    Vault();
    ~Vault();

    void createSalt();          // Creates a salt for hashing the password
    bool deriveKey();           // Create key for accessing file. 
    void getMasterPassword();   // Get user created Master Password
    bool verifyPassword();      // Verifies masterPoassword when entered by user
    void loadVault();           // Loads the encypted file
    void saveVault();           // Save added contents to vault.
    void addCredentials();      // stores credintials to encrypted file.
    void deleteCredential();    // Delete a credintial in the encrypted file. 

    const std::vector<Credential>& getCredentials() const {return credentials;}
};


#endif // VAULT_HPP