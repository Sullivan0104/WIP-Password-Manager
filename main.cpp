#include "Vault.hpp"
#include "Display.hpp"

int main() 
{
    Vault vault;

    vault.createSalt();
    vault.deriveKey();
    vault.verifyPassword();
    return 0;
}