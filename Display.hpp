/*
Responsible for:
- Displaying the credintials stored in the vault.
*/

#include <iostream>
#include "Vault.hpp"

class Display
{
public:
    Display() = default;
    ~Display() = default;

    void show(const Vault& vault) {
        const auto& creds = vault.getCredentials();

        if (creds.empty()) {
            std::cout << "No credentials stored.\n";
            return;
        }

        std::cout << "\nStored Credentials:\n";
        std::cout << "--------------------------------\n";

        for (const auto& cred : creds) {
            std::cout << "Site: " << cred.site << "\n";
            std::cout << "Username: " << cred.username << "\n";

            // Convert password to string for display
            std::string pw(reinterpret_cast<const char*>(cred.password), cred.passwordLength);
            std::cout << "Password: " << pw << "\n";
            std::cout << "--------------------------------\n";
        }
    }
};

