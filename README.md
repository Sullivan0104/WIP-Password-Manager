# WIP-Password-Manager
Lightweight password vault written in C++. Derives the key from a master-password using argon2id, then stores every credential in a single encrypted binary file. Simple CML menu is used for the User to view and add credentials. All sensitive data kept in sodium‑locked memory that is securely wiped on exit. Not the final version. 
# Goal: 
Complete a practical C++ Password manager utilizing OOP and efficent and secure memory management.
# Current Features
| Feauture | Description |
|-----:|-----------|
|     Argon2id | Derives a master key from the user’s master password.|
|     Authenticated Encryption| Every secret encrypted with libsodium.|
|     Zero‑Access Memory| Sensitive material lives in memory that is locked and wiped as soon as it’s no longer needed.|
<img width="951" height="707" alt="ExampleVault" src="https://github.com/user-attachments/assets/d3922494-9a7f-4836-8172-aa7b01885f84" />
# Planned Features
| Feauture | Description |
|-----:|-----------|
|     Argon2id | Derives a master key from the user’s master password.|
|     Authenticated Encryption| Every secret encrypted with libsodium.|
|     Zero‑Access Memory| Sensitive material lives in memory that is locked and wiped as soon as it’s no longer needed.|
