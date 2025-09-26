#include "Display.hpp"
#include <cstdlib>

/*______________________________________________________________________________
- Implementation for Display.hpp
______________________________________________________________________________*/

void clearScreen() {
    std::system(CLEAR_CMD);
}

void Display::togglePasswordVisibility()
{
    showPasswords = !showPasswords;
}
/*______________________________________________________________________________
- Display of credentials
______________________________________________________________________________*/
void Display::show(const Vault& vault) {
    const auto& creds = vault.getCredentials();

    if (creds.empty()) 
    {
        std::cout << "No credentials stored.\n";
        return;
    }

    std::cout << "\nStored Credentials:\n";
    std::cout << "________________________________________\n";

    for (const auto& cred : creds) {
        std::cout << "Site    : " << cred.site << "\n";
        std::cout << "Username: " << cred.username << "\n";
        
        if (showPasswords) 
        {
            // Plain text
            std::string pw(reinterpret_cast<const char*>(cred.password), cred.passwordLength);
            std::cout << "Password: " << pw << "\n";
            } else 
            {
                // Masked with '*'
                std::cout << "Password: " << std::string(cred.passwordLength, '*') << "\n";
            }
            std::cout << "________________________________________\n";
        }
    }
/*______________________________________________________________________________
- Menu and title display
______________________________________________________________________________*/
void Display::refreshUI(Vault& vault) 
{
    clearScreen();
    std::cout << R"(
________________________________________________________________________
  _____                                    _  __      __         _ _   
 |  __ \                                  | | \ \    / /        | | |  
 | |__) |_ _ ___ _____      _____  _ __ __| |  \ \  / /_ _ _   _| | |_ 
 |  ___/ _` / __/ __\ \ /\ / / _ \| '__/ _` |   \ \/ / _` | | | | | __|
 | |  | (_| \__ \__ \\ V  V / (_) | | | (_| |    \  / (_| | |_| | | |_ 
 |_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_|     \/ \__,_|\__,_|_|\__|
________________________________________________________________________       
    )";

    show(vault);

    std::cout << "\n______________ Menu _______________ \n"
                    << "1) Toggle Password visibility\n"
                    << "2) Add a new credential\n"
                    << "3) Quit (save & exit)\n"
                    << "4) Delete credential\n"
                    << "Choose an option [1-4]: " << std::flush;
}