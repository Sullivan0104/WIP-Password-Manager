#include <iostream>
#include <sodium.h>
#include <vector>
#include <fstream>

/*______________________________________________________________________________
Vault Class:
 - Setting the master password. 
 - Salting and hashing passwords. 
 - Storing credintials in a encypted file.
 - Verifying the master password
______________________________________________________________________________*/

class Vault
{
private:
    const size_t saltLength {16};       // 16 bytes for the salt.
    unsigned char* salt {};             // Generated with libsodium
    unsigned char* masterPassword {};   // User input for masterPassword
    size_t masterPasswordLength {};     // track length for freeing
    unsigned char* masterKey {};        // key derived from password & salt
    size_t masterKeyLength {};          // Track Length for freeing

    struct Credential;                      // Website/username/password
    std::vector<Credential> credentials;



public:
    Vault();
    ~Vault();

    void createSalt();          // Creates a salt for hashing the password
    bool deriveKey();           // Create key for accessing file. 
    void getMasterPassword();  // Get user created Master Password
    void verifyPassword();      // Verifies masterPoassword when entered by user
    void loadVault();           // Loads the encypted file
    void saveVault();           // Save added contents to vault.
    void addCredintials();      // stores credintials to encrypted file. 

};

/*______________________________________________________________________________
Struct for credintials
______________________________________________________________________________*/
struct Vault::Credential 
{
    std::string site;
    std::string username;
    unsigned char* password {};
};

/*______________________________________________________________________________
    - Intilizses liibsodium for argon2id use
    - Allocates bytes for saltLength
______________________________________________________________________________*/
Vault::Vault()
{
    if (sodium_init() < 0) 
    {
        std::cerr << "libsodium init failed\n";
    }

    salt = (unsigned char*)sodium_malloc(saltLength);
    if(!salt)
    {
        throw std::runtime_error("Failed to allocate secure memory for salt.");
    }
}
/*______________________________________________________________________________
    - Erase salt, masterkey, and masterPassword and free their memory. 
______________________________________________________________________________*/
Vault::~Vault() 
{
    if (salt) 
    {
        sodium_memzero(salt, saltLength);
        sodium_free(salt);
        salt = nullptr;
    }

    if (masterKey) 
    {
        sodium_memzero(masterKey, masterKeyLength);
        sodium_free(masterKey);
        masterKey = nullptr;
        masterKeyLength = 0;
    }

    if (masterPassword)
    {
        sodium_memzero(masterPassword, masterPasswordLength);
        sodium_free(masterPassword);
        masterPassword = nullptr;
        masterPasswordLength = 0;
    }
}
/*______________________________________________________________________________
    - Generate a random salt.
______________________________________________________________________________*/
void Vault::createSalt()
{
    randombytes_buf(salt, saltLength);

    /*TESTING*/
    std::cout << "Salt (hex): ";
    for(size_t i {0}; i < saltLength; ++i)
    {
        printf("%02x", salt[i]);
    }
    std::cout << "\n";

}
/*______________________________________________________________________________
    - Get masterPassword from user
______________________________________________________________________________*/
void Vault::getMasterPassword()
{
    std::cout << "Enter Master Password: ";
    scanf("%s", masterPassword);
}
/*______________________________________________________________________________
    - Generate a argon2id key using masterPassword abnd salt
______________________________________________________________________________*/
bool Vault::deriveKey()
{
    
}
/*______________________________________________________________________________
    - Save salt to file for later masterPassword verification
    - May save credintials added to encypted file here as well in future
______________________________________________________________________________*/
void Vault::saveVault()
{

}
/*______________________________________________________________________________
    - OpenVault for reading. Must verifiy password first!
______________________________________________________________________________*/
void Vault::loadVault()
{

}
/*______________________________________________________________________________
    - Add creidentials to encrypted file
______________________________________________________________________________*/
void Vault::addCredintials()
{
    
}