#include "Vault.hpp"
#include "Display.hpp"
#include <iostream>
#include <limits>
#include <cstdlib> 

#ifdef _WIN32
    constexpr const char* CLEAR_CMD = "cls";
#else
    constexpr const char* CLEAR_CMD = "clear";
#endif
inline void clearScreen() { std::system(CLEAR_CMD); }

void refreshUI(Vault& vault)
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

    Display disp;
    disp.show(vault);  

    std::cout << "\n______________ Menu _______________ \n"
              << "1) Show all stored credentials\n"
              << "2) Add a new credential\n"
              << "3) Quit (save & exit)\n"
              << "4) Delete credential\n"
              << "Choose an option [1-4]: " << std::flush;
}

int main()
{
    Vault vault;

    vault.createSalt();
    if (!vault.verifyPassword()) {
        std::cerr << "SENDING DRONES TO TERMINATE YOU!\n";
        return 1;
    }

    vault.loadVault();

    bool running = true;
    while (running) {
        refreshUI(vault);                 

        int choice = 0;
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
            case 1: {                        
                break;
            }
            case 2: {                       
                vault.addCredentials();   
                break;
            }
            case 3: {                         
                running = false;
                break;
            }
            case 4: {
                vault.deleteCredential();
                break;
            }
            default:
                std::cout << "Invalid selection - please type 1, 2 or 3.\n";
        }
    }

    vault.saveVault();                     
    std::cout << "Goodbye!\n";
    return 0;
}