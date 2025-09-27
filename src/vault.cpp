#include "Vault.hpp"

#include <iostream>
#include <sodium.h>
#include <fstream>
#include <cstring>
#include <termios.h>
#include <unistd.h>
#include <algorithm>
#include <thread>
#include <chrono>
#include <string>


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

        randombytes_buf(markerNonce, sizeof markerNonce);
        markerCipher.resize(markerLen + crypto_secretbox_MACBYTES);

        crypto_secretbox_easy(markerCipher.data(),
                              (const unsigned char*)marker, markerLen,
                              markerNonce, masterKey);

        std::ofstream ofs("vault.bin", std::ios::binary);
        ofs.write((char*)salt, saltLength);
        ofs.write((char*)markerNonce, sizeof markerNonce);
        ofs.write((char*)markerCipher.data(), markerCipher.size());
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
bool Vault::verifyPassword()
{
    std::ifstream ifs("vault.bin", std::ios::binary);
    if (!ifs) {
        std::cerr << "Vault file not found.\n";
        return false;
    }

    ifs.read((char*)salt, saltLength);
    ifs.read((char*)markerNonce, sizeof markerNonce);

    size_t cipherLen = strlen("VAULT") + crypto_secretbox_MACBYTES;
    markerCipher.resize(cipherLen);
    ifs.read((char*)markerCipher.data(), cipherLen);

    ifs.close();

    getMasterPassword();
    if (!deriveKey()) {
        std::cerr << "Key derivation failed.\n";
        return false;
    }

    std::vector<unsigned char> decrypted(strlen("VAULT"));
    if (crypto_secretbox_open_easy(decrypted.data(),
                                   markerCipher.data(), markerCipher.size(),
                                   markerNonce, masterKey) != 0) {
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
    std::ofstream ofs("vault.bin", std::ios::binary | std::ios::trunc);
    if (!ofs) throw std::runtime_error("Failed to open vault file for writing.");

    // Write header using member variables
    ofs.write((char*)salt, saltLength);
    ofs.write((char*)markerNonce, sizeof markerNonce);
    ofs.write((char*)markerCipher.data(), markerCipher.size());

    for (auto& cred : credentials) {
        uint32_t siteLen = cred.site.size();
        ofs.write((char*)&siteLen, sizeof siteLen);
        ofs.write(cred.site.data(), siteLen);

        uint32_t userLen = cred.username.size();
        ofs.write((char*)&userLen, sizeof userLen);
        ofs.write(cred.username.data(), userLen);

        unsigned char pwNonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(pwNonce, sizeof pwNonce);

        std::vector<unsigned char> pwCipher(cred.passwordLength + crypto_secretbox_MACBYTES);
        crypto_secretbox_easy(pwCipher.data(), cred.password, cred.passwordLength, pwNonce, masterKey);

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
    const size_t MAX_PASSWORD_LEN = 1024;
    unsigned char* pwBuffer = (unsigned char*)sodium_malloc(MAX_PASSWORD_LEN);
    size_t length = 0;
    char ch;

    while (std::cin.get(ch) && ch != '\n' && length < MAX_PASSWORD_LEN)
    {
        pwBuffer[length++] = static_cast<unsigned char>(ch);
    }
    
    if (length == 0)
    {
        sodium_free(pwBuffer);
        std::cout << "Empty passwords are invalid.\n";
        return;
    }

    cred.passwordLength = length;
    cred.password = (unsigned char*)sodium_malloc(length);

    if(!cred.password)
    {
        sodium_memzero(pwBuffer, length);
        sodium_free(pwBuffer);
        throw std::runtime_error("Secure memory allocation failed.");
    }
    
    memcpy(cred.password, pwBuffer, length);

    sodium_memzero(pwBuffer, length);
    sodium_free(pwBuffer);

    credentials.push_back(std::move(cred));

    std::cout << "Credintials Successfully Added.\n";
    
}
/*______________________________________________________________________________
    - Delete a credential from the vault.
    - User provides site/username to identify which one to delete.
______________________________________________________________________________*/
void Vault::deleteCredential()
{
    if (credentials.empty()) {
        std::cout << "No credentials available to delete.\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }

    std::string siteInput, userInput;
    std::cout << "Enter Site of credential to delete: ";
    std::getline(std::cin, siteInput);

    std::cout << "Enter Username of credential to delete: ";
    std::getline(std::cin, userInput);

    std::cout << "Are you sure you want to delete this credential: \n";
    std::cout << "Website: "<< siteInput << '\n';
    std::cout << "Username: " << userInput << '\n';
    std::string verification;
    std::cout << "[Yes/No]: ";
    std::getline(std::cin, verification);
    
    if(verification == "No" || verification == "no")
    {
        return;
    }
    else if(verification == "Yes" || verification == "yes")
    {
            
    }
    else
    {
        std::cout << "Invalid Input. Deletion cancelled.\n";
        std::this_thread::sleep_for(std::chrono::seconds(1));
        return;
    }

    auto it = std::find_if(credentials.begin(), credentials.end(),
        [&](const Credential& cred) {
            return cred.site == siteInput && cred.username == userInput;
        });

    if (it == credentials.end()) {
        std::cout << "No matching credential found.\n";
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return;
    }

    if (it->password) {
        sodium_memzero(it->password, it->passwordLength);
        sodium_free(it->password);
        it->password = nullptr;
        it->passwordLength = 0;
    }

    credentials.erase(it);

    saveVault();

}