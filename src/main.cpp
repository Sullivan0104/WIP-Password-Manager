#include "Vault.hpp"
#include "Display.hpp"

#include <iostream>
#include <limits>

/*______________________________________________________________________________
Main:
- Logic for application.
______________________________________________________________________________*/

int main()
{
    Vault vault;

    vault.createSalt();
    if (!vault.verifyPassword()) {
        std::cerr << "SENDING DRONES TO TERMINATE YOU!\n";
        return 1;
    }

    vault.loadVault();

    Display disp;

    bool running = true;
    while (running) {
        disp.refreshUI(vault); 

        int choice = 0;
        std::cin >> choice;
        // clears newline
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
            case 1: {
                disp.togglePasswordVisibility();
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
                std::cout << "Invalid selection - please type 1, 2, or 3.\n";
        }
    }

    vault.saveVault();
    std::cout << "Goodbye!\n";
    return 0;
}
