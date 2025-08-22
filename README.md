# LazyNmap 💤

<p align="center">
  <img src=".github/lazynmap.gif" alt="LazyNmap Demo GIF" width="600"/>
</p>

A user-friendly, TUI-driven wrapper for `nmap` written in Go. Designed for Termux users, sysadmins, and security enthusiasts who want the power of nmap without memorizing complex flags.

This tool guides you through creating sophisticated nmap scans, shows you the exact command it will run, and presents the output in a clean, scrollable interface.

---

## ✨ Features

- **Rich Interactive TUI:** A clean, modern terminal interface built with Bubble Tea.
- **Guided Workflow:** Guides you step-by-step through selecting a scan, setting options, and choosing output formats.
- **Expert Presets:** A curated list of powerful, real-world nmap scans for discovery, enumeration, vulnerability scanning, and evasion.
- **Command Preview:** See the exact `nmap` command before you run it—a great way to learn!
- **Scan History:** Automatically saves your scan history. View and re-run any previous command with a single keypress.
- **Flexible Targeting:** Scan a single host, a CIDR range, or provide a text file of targets using the `-iL` flag automatically.
- **Customizable Scans:**
    - Choose timing templates (`-T0` to `-T5`).
    - Select verbosity levels (`-v`, `-vv`).
    - Enter any custom `nmap` flags for full control.
- **Save & Export:** Save scan results to a uniquely named file in Normal (`.txt`), Grepable (`.gnmap`), or XML (`.xml`) format.
- **Clipboard Support:** Copy any generated command to your clipboard with a single keypress (`c`).
- **"Go Back" Functionality:** Made a mistake? Just press `esc` to go back to the previous step.

## 📦 Installation

### Prerequisites

You **must** have the `nmap` package installed on your system.
- **Termux:** `pkg install nmap`
- **Debian/Ubuntu:** `sudo apt install nmap`
- **Fedora:** `sudo dnf install nmap`
- **macOS:** `brew install nmap`

### Option 1: From Binaries (Recommended)

1. Go to the [**Releases Page**](https://github.com/rkstudio585/lazynmap/releases).
2. Download the pre-compiled binary for your operating system (e.g., `lazynmap`).
3. Make it executable: `chmod +x lazynmap`
4. Run it: `./lazynmap`
   *(Optional: Move it to your PATH to run it from anywhere: `sudo mv lazynmap /usr/local/bin/lazynmap`)*

### Option 2: From Source (Requires Go)

If you have Go (1.18+) installed:
```bash
go install github.com/rkstudio585/lazynmap@latest
```
The binary will be installed in your `$GOPATH/bin` directory.

## 🚀 Usage

Simply run the executable:
```bash
./lazynmap
```
Use the arrow keys to navigate, `enter` to select, and `esc` to go back. Follow the on-screen prompts to build and execute your scan.

## 🛠️ Build From Source

Clone the repository and build the project:
```bash
git clone https://github.com/rkstudio585/lazynmap.git
cd lazynmap
go build -o lazymap .
```

### Cross-Compile for other systems (The Pro Move):

*   **For Termux (arm64):**
    ```bash
    go build -o lazymap .
    ```
*   **For Linux (amd64):**
    ```bash
    GOOS=linux GOARCH=amd64 go build -o lazymap .
    ```
*   **For Windows (amd64):**
    ```bash
    GOOS=windows GOARCH=amd64 go build -o lazymap.exe .
    ```
*   **For macOS (Intel amd64):**
    ```bash
    GOOS=darwin GOARCH=amd64 go build -o lazymap .
    ```
*   **For macOS (Apple Silicon arm64):**
    ```bash
    GOOS=darwin GOARCH=arm64 go build -o lazymap .
    ```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
