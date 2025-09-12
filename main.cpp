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

// ---------- UI refresh ----------
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
    disp.show(vault);   // optional – shows the table each time

    std::cout << "\n--- Menu -------------------------------------------------\n"
              << "1) Show all stored credentials\n"
              << "2) Add a new credential\n"
              << "3) Quit (save & exit)\n"
              << "Choose an option [1‑3]: " << std::flush;
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
        refreshUI(vault);                     // <-- draw fresh UI

        int choice = 0;
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
            case 1: {                         // Show (already done by refreshUI)
                // Nothing else needed – the table is already printed.
                break;
            }
            case 2: {                         // Add a credential
                vault.addCredentials();       // <-- mutates vault
                // Optionally autosave here:
                // vault.saveVault();
                break;
            }
            case 3: {                         // Quit
                running = false;
                break;
            }
            default:
                std::cout << "Invalid selection – please type 1, 2 or 3.\n";
        }
    }

    vault.saveVault();                       // final persist
    std::cout << "Good‑bye!\n";
    return 0;
}