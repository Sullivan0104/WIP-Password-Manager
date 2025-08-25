#include <iostream>
#include <sodium.h>
#include <vector>
#include <fstream>
#include <cstring>
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
    size_t passwordLength {};
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
    - Erase sensitive data. 
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

    for(auto&cred : credentials)
    {
        if(cred.password)
        {
            sodium_memzero(cred.password, cred.passwordLength);
            sodium_free(cred.password);
        }
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
    std::vector<char> input(256); // limit input size (e.g. 256 chars max)
    std::cout << "Enter Master Password: ";
    std::cin.getline(input.data(), input.size());

    masterPasswordLength = strnlen(input.data(), input.size());
    masterPassword = (unsigned char*)sodium_malloc(masterPasswordLength);

    memcpy(masterPassword, input.data(), masterPasswordLength);

    // Wipe temporary buffer
    sodium_memzero(input.data(), input.size());
}
/*______________________________________________________________________________
    - Generate a argon2id key using masterPassword abnd salt
______________________________________________________________________________*/
bool Vault::deriveKey()
{    
    masterKeyLength = crypto_secretbox_KEYBYTES;
    masterKey = (unsigned char*)sodium_malloc(masterKeyLength);
    if (!masterKey)
        return false;

    // Argon2id parameters: opslimit, memlimit
    const unsigned long long opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    const size_t memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;

    if (crypto_pwhash(masterKey, masterKeyLength,
                      (const char*)masterPassword, masterPasswordLength,
                      salt,
                      opslimit, memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        return false; // failed to derive key
    }

    return true;
    
}
/*______________________________________________________________________________
    - Save salt to file for later masterPassword verification
    - May save credintials added to encypted file here as well in future
______________________________________________________________________________*/
void Vault::saveVault()
{
    std::ofstream ofs("vault.bin", std::ios::binary);
    ofs.write((char*)salt, saltLength);

    // TODO: Encrypt credentials with masterKey and write
    ofs.close();
}
/*______________________________________________________________________________
    - OpenVault for reading. Must verifiy password first!
______________________________________________________________________________*/
void Vault::loadVault()
{
    std::ifstream ifs("vault.bin", std::ios::binary);
    if (!ifs) return;

    ifs.read((char*)salt, saltLength);

    // TODO: prompt for password -> deriveKey() -> decrypt credentials
    ifs.close();
}
/*______________________________________________________________________________
    - Add creidentials to encrypted file
______________________________________________________________________________*/
void Vault::addCredintials()
{
    Credential cred;
    
    std::cout << "Enter Credential (site, username, password): ";
    std::string line;
    std::getline(std::cin, line);

    // Parse through input, seperate site, username, and password
    size_t firstComma {line.find(',')};
    size_t secondComma {line.find(',', firstComma + 1)};

    if(firstComma == std::string::npos || secondComma == std::string::npos)
    {
        std::cerr << "Invalid Input Format!\n";
    }

    cred.site = line.substr(0, firstComma);
    cred.username = line.substr(firstComma+1, secondComma-firstComma-1);

    std::string passwordString = line.substr(secondComma + 1);

    // Trim whitespace around fields 
    auto trim = [](std::string& s) {
        size_t start = s.find_first_not_of(" \t");
        size_t end   = s.find_last_not_of(" \t");
        if (start == std::string::npos) { s.clear(); return; }
        s = s.substr(start, end - start + 1);
    };
    trim(cred.site);
    trim(cred.username);
    trim(passwordString);

    // Copy password into secure memory
    cred.passwordLength = passwordString.size();
    cred.password = (unsigned char*)sodium_malloc(cred.passwordLength);

    memcpy(cred.password, passwordString.data(), passwordString.size());
    // Erase the string data
    sodium_memzero(passwordString.data(), passwordString.size());

    credentials.push_back(std::move(cred));

    std::cout << "Credintials Successfully Added.\n";
    
}