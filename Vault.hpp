#ifndef VAULT_HPP
#define VAULT_HPP

#include <iostream>
#include <sodium.h>
#include <vector>
#include <fstream>
#include <cstring>
#include <termios.h>
#include <unistd.h>

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
    void getMasterPassword();   // Get user created Master Password
    bool verifyPassword();      // Verifies masterPoassword when entered by user
    void loadVault();           // Loads the encypted file
    void saveVault();           // Save added contents to vault.
    void addCredentials();      // stores credintials to encrypted file. 

    const std::vector<Credential>& getCredentials() const {return credentials;}
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
    - Generate a random salt. Will check if salt already exist in vaule file. 
______________________________________________________________________________*/
void Vault::createSalt()
{
    std::ifstream ifs("vault.bin", std::ios::binary);
    if (ifs.is_open()) {
        ifs.read((char*)salt, saltLength);
    } else {
        // Generate a new salt
        randombytes_buf(salt, saltLength);

        // Get a master password from user and derive a key
        getMasterPassword();
        if (!deriveKey()) {
            throw std::runtime_error("Failed to derive key.");
        }

        // Prepare known marker
        const char* marker = "VAULT";
        size_t markerLen = strlen(marker);

        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, sizeof nonce);

        std::vector<unsigned char> cipher(markerLen + crypto_secretbox_MACBYTES);

        crypto_secretbox_easy(cipher.data(),
                              (const unsigned char*)marker, markerLen,
                              nonce, masterKey);

        // Save salt, nonce, and marker ciphertext to file
        std::ofstream ofs("vault.bin", std::ios::binary);
        ofs.write((char*)salt, saltLength);
        ofs.write((char*)nonce, sizeof nonce);
        ofs.write((char*)cipher.data(), cipher.size());
        ofs.close();
    }
}

/*______________________________________________________________________________
    - Get masterPassword from user
______________________________________________________________________________*/
void Vault::getMasterPassword()
{
    termios oldt{}, newt{};
    if(tcgetattr(STDIN_FILENO, &oldt) == -1)
    {
        throw std::runtime_error("tcgetattr failed");
    }
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) == -1)
    {
        throw std::runtime_error("tcsetattr failed");
    }

    std::vector<char> input(256); // limit input size (e.g. 256 chars max)
    std::cout << "Enter Master Password: ";
    std::cin.getline(input.data(), input.size());

    if (tcsetattr(STDERR_FILENO, TCSAFLUSH, &oldt) == -1)
    {
        std::cerr << "/nWarning: failed to restore terminal settings.\n";
    }
    std::cout << '\n';

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
    const unsigned long long opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
    const size_t memlimit = crypto_pwhash_MEMLIMIT_SENSITIVE;

    if (crypto_pwhash(masterKey, masterKeyLength,
                      (const char*)masterPassword, masterPasswordLength,
                      salt,
                      opslimit, memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        return false; 
    }

    return true;
    
}

/*______________________________________________________________________________
    - Verfy Password
______________________________________________________________________________*/
bool  Vault::verifyPassword()
{
    // Load salt + marker from file
    std::ifstream ifs("vault.bin", std::ios::binary);
    if (!ifs) {
        std::cerr << "Vault file not found.\n";
        return false;
    }

    ifs.read((char*)salt, saltLength);

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    ifs.read((char*)nonce, sizeof nonce);

    // Read marker ciphertext (length is known: strlen("VAULT") + MACBYTES)
    size_t cipherLen = strlen("VAULT") + crypto_secretbox_MACBYTES;
    std::vector<unsigned char> cipher(cipherLen);
    ifs.read((char*)cipher.data(), cipherLen);

    ifs.close();

    // Ask user for password, derive key
    getMasterPassword();
    if (!deriveKey()) {
        std::cerr << "Key derivation failed.\n";
        return false;
    }

    // Attempt to decrypt marker
    std::vector<unsigned char> decrypted(strlen("VAULT"));
    if (crypto_secretbox_open_easy(decrypted.data(),
                                   cipher.data(), cipher.size(),
                                   nonce, masterKey) != 0) {
        std::cerr << "Wrong master password!\n";
        return false;
    }

    std::cout << "Password verified successfully.\n";
    return true;
}

/*______________________________________________________________________________
    - Save salt to file for later masterPassword verification
    - May save credintials added to encypted file here as well in future
______________________________________________________________________________*/
void Vault::saveVault()
{
    std::fstream ofs("vault.bin", std::ios::binary | std::ios::in | std::ios::out);
    if (!ofs) {
        throw std::runtime_error("Vault file not found.");
    }

    // Move past the header: salt + marker nonce + marker cipher
    size_t headerSize = saltLength + crypto_secretbox_NONCEBYTES + strlen("VAULT") + crypto_secretbox_MACBYTES;
    ofs.seekp(headerSize, std::ios::beg);

    // Now write credentials
    for (auto& cred : credentials) {
        // Write site
        uint32_t siteLen = cred.site.size();
        ofs.write((char*)&siteLen, sizeof siteLen);
        ofs.write(cred.site.data(), siteLen);

        // Write username
        uint32_t userLen = cred.username.size();
        ofs.write((char*)&userLen, sizeof userLen);
        ofs.write(cred.username.data(), userLen);

        // Encrypt password
        unsigned char pwNonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(pwNonce, sizeof pwNonce);

        std::vector<unsigned char> pwCipher(cred.passwordLength + crypto_secretbox_MACBYTES);
        crypto_secretbox_easy(pwCipher.data(),
                              cred.password, cred.passwordLength,
                              pwNonce, masterKey);

        // Write nonce + ciphertext length + ciphertext
        ofs.write((char*)pwNonce, sizeof pwNonce);

        uint32_t cipherLen = pwCipher.size();
        ofs.write((char*)&cipherLen, sizeof cipherLen);
        ofs.write((char*)pwCipher.data(), cipherLen);
    }

    ofs.close();
}


/*______________________________________________________________________________
    - OpenVault for reading. Must verifiy password first!
______________________________________________________________________________*/
void Vault::loadVault()
{
    std::ifstream ifs("vault.bin", std::ios::binary);
    if (!ifs) {
        std::cerr << "No vault found.\n";
        return;
    }

    // Read salt
    ifs.read((char*)salt, saltLength);

    // Read marker nonce + ciphertext
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    ifs.read((char*)nonce, sizeof nonce);

    size_t markerLen = strlen("VAULT") + crypto_secretbox_MACBYTES;
    std::vector<unsigned char> markerCipher(markerLen);
    ifs.read((char*)markerCipher.data(), markerLen);

    // Verify password (deriveKey already called before loadVault)
    std::vector<unsigned char> decrypted(strlen("VAULT"));
    if (crypto_secretbox_open_easy(decrypted.data(),
                                   markerCipher.data(), markerCipher.size(),
                                   nonce, masterKey) != 0) {
        std::cerr << "Wrong master password.\n";
        return;
    }

    // Read credentials until EOF
    credentials.clear();
    while (ifs.peek() != EOF) {
        Credential cred;

        uint32_t siteLen, userLen, cipherLen;

        ifs.read((char*)&siteLen, sizeof siteLen);
        if (ifs.eof()) break;
        cred.site.resize(siteLen);
        ifs.read(&cred.site[0], siteLen);

        ifs.read((char*)&userLen, sizeof userLen);
        cred.username.resize(userLen);
        ifs.read(&cred.username[0], userLen);

        unsigned char pwNonce[crypto_secretbox_NONCEBYTES];
        ifs.read((char*)pwNonce, sizeof pwNonce);

        ifs.read((char*)&cipherLen, sizeof cipherLen);
        std::vector<unsigned char> pwCipher(cipherLen);
        ifs.read((char*)pwCipher.data(), cipherLen);

        // Decrypt password
        cred.passwordLength = cipherLen - crypto_secretbox_MACBYTES;
        cred.password = (unsigned char*)sodium_malloc(cred.passwordLength);
        if (crypto_secretbox_open_easy(cred.password,
                                       pwCipher.data(), pwCipher.size(),
                                       pwNonce, masterKey) != 0) {
            std::cerr << "Decryption failed for a credential.\n";
            sodium_free(cred.password);
            continue;
        }

        credentials.push_back(std::move(cred));
    }
}
/*______________________________________________________________________________
    - Add creidentials to encrypted file
______________________________________________________________________________*/
void Vault::addCredentials()
{
    Credential cred;

    std::cout << "Site: ";
    std::getline(std::cin, cred.site);

    std::cout << "Username: ";
    std::getline(std::cin, cred.username);

    std::cout << "Password: ";
    std::string pw;
    std::getline(std::cin, pw);
    cred.passwordLength = pw.size();
    cred.password = (unsigned char*)sodium_malloc(cred.passwordLength);
    memcpy(cred.password, pw.data(), cred.passwordLength);
    sodium_memzero(pw.data(), pw.size());

    credentials.push_back(std::move(cred));

    std::cout << "Credintials Successfully Added.\n";
    
}

#endif // VAULT_HPP