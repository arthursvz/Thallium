# Thallium – Linux Usage Guide

This guide explains how to use the Thallium executables on Linux to encrypt and decrypt your files and folders securely.

## Prerequisites
- Download the Linux executables (`encryptor`, `decryptor`, etc.) from the repository.
- Ensure you have execution permissions:
  ```bash
  chmod +x encryptor decryptor
  ```
- Place the executables in the root of your project, next to the `data/` directory.

## Usage

### Encrypt a File
```bash
./encryptor
```
- Choose `f` for file.
- Enter the path to the file (relative to `data/`).
- Choose your key management option (manual or auto-generated).

### Encrypt a Folder
```bash
./encryptor
```
- Choose `d` for directory.
- Enter the path to the folder (relative to `data/`).
- Choose to use a single key, a key per file, or an auto-generated folder key.

### Decrypt a File or Folder
```bash
./decryptor
```
- Follow the prompts to select the file/folder and provide the key or key file as needed.

## Notes
- All encrypted files and keys are stored in the `data/` directory.
- The cleaner utility can be used to remove `.enc` and `.key` files:
  ```bash
  ./cleaner <folder_relative_to_data>
  ```
- No Python installation is required to use the executables.

## Troubleshooting
- If you see a "Permission denied" error, use `chmod +x` as shown above.
- ASCII art may display differently depending on your terminal.

## License
This project is licensed under the Apache 2.0 License.

