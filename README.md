# Binary String Extractor Mini

A modern, user-friendly PyQt6 utility for extracting readable strings from binary files (executables, DLLs, firmware, etc.).

- **Features:**
  - Select any binary file and extract embedded ASCII/Unicode strings
  - Filter by minimum string length and encoding (ASCII, UTF-8, UTF-16 LE/BE)
  - Modern, dark-themed GUI (PyQt6 + QSS)
  - Results include byte offsets and encoding labels
  - Save results to a text file
  - Fast, chunked processing (handles large files)
  - Windows EXE release (no Python required)

## Installation & Usage

### Run from Source
1. Install Python 3.8+ and PyQt6:
   ```sh
   pip install PyQt6
   ```
2. Run:
   ```sh
   python BinaryStringExtractorMini.py
   ```

### Windows Executable
- Download the latest `.exe` from the [Releases](https://github.com/ReaIKw/binary-string-extractor-mini/releases) page and run it directly (no install needed).

## Screenshot
![screenshot](https://user-images.githubusercontent.com/181601409/placeholder.png)

## License
MIT
