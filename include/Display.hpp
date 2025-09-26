#ifndef DISPLAY_HPP
#define DISPLAY_HPP

#include <iostream> 
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

inline void clearScreen();

class Display
{
private:
    bool showPasswords = false;

public:
    Display() = default;
    ~Display() = default;

    void togglePasswordVisibility();
    void show(const Vault& vault);
    void refreshUI(Vault& vault);

};

#endif // DISPLAY_HPP

