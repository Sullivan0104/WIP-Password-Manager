#ifndef DISPLAY_HPP
#define DISPLAY_HPP

#include <iostream>
#include <cstdlib>   
#include <string>
#include "Vault.hpp"

/*______________________________________________________________________________
Display class:
- Displays the UI.
______________________________________________________________________________*/

#ifdef _WIN32
    constexpr const char* CLEAR_CMD = "cls";
#else
    constexpr const char* CLEAR_CMD = "clear";
#endif

inline void clearScreen() {
    std::system(CLEAR_CMD);
}

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
        std::cout << "________________________________________\n";

        for (const auto& cred : creds) {
            std::cout << "Site    : " << cred.site << "\n";
            std::cout << "Username: " << cred.username << "\n";

            std::string pw(reinterpret_cast<const char*>(cred.password), cred.passwordLength);
            std::cout << "Password: " << pw << "\n";
            std::cout << "________________________________________\n";
        }
    }

    void refreshUI(Vault& vault) {
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
                  << "1) Add a new credential\n"
                  << "2) Quit (save & exit)\n"
                  << "3) Delete credential\n"
                  << "Choose an option [1-3]: " << std::flush;
    }
};

#endif // DISPLAY_HPP

