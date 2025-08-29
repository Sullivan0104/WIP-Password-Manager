#include "Vault.hpp"
#include "Display.hpp"

int main() 
{
    Vault vault;

    vault.createSalt();

    if(!vault.verifyPassword())
    {
        std::cerr << "SENDING DRONES TO TERMINATE YOU!\n";
        return 1;
    }

    vault.loadVault();

    Display Display;
    Display.show(vault);

    vault.addCredentials();

    vault.saveVault();

    return 0;
}