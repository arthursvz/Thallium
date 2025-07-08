# Thallium Executables

Thallium provides simple, secure tools to encrypt and decrypt files or folders using strong AES encryption. This repository contains only the ready-to-use executables for Linux, Windows, or Mac.

## Features
- Encrypt or decrypt files and folders (recursively)
- Choose a single key, a key per file, or an auto-generated folder key
- No Python installation required

## Usage

1. **Download the executable for your system** (e.g. `encryptor` or `decryptor`).
2. Place the executable in the same directory as your `data/` folder.
3. Run from a terminal:
   ```bash
   ./encryptor
   # or
   ./decryptor
   ```
4. Follow the on-screen prompts to select files/folders and manage keys.

## Notes
- All data and key files are managed in the `data/` directory.
- No installation or dependencies required.
- For security, keep your keys safe. Losing a key means losing access to your data.

## License

This project is licensed under the Apache 2.0 License.
