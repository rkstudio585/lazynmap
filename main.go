// main.go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mitchellh/go-homedir"
)

const (
	historyFilename = ".lazy-nmap-history.json"
	maxHistoryItems = 25
)

type appState int

const (
	stateChoosingScan appState = iota
	stateEnteringTarget
	stateEnteringCustomFlags
	stateChoosingNSE
	stateChoosingTiming
	stateChoosingVerbosity
	stateSavingOutput
	stateShowingHistory
	stateConfirming
	stateScanning
	stateShowingResults
)

var (
	titleStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true).Margin(0, 0, 1, 0)
	docStyle          = lipgloss.NewStyle().Margin(1, 2)
	helpStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	promptStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("7")).Bold(true)
	cmdStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	errorStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	spinnerStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))
	viewportHeader    = lipgloss.NewStyle().Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230")).Bold(true).Padding(0, 1)
	viewportFooter    = lipgloss.NewStyle().Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230")).Padding(0, 1)
	confirmationStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Bold(true)
)

type scanType struct {
	title       string
	description string
	commandFmt  string
}

func (s scanType) Title() string       { return s.title }
func (s scanType) Description() string { return s.description }
func (s scanType) FilterValue() string { return s.title }

type choiceItem struct {
	title string
	value string
}

func (c choiceItem) Title() string       { return c.title }
func (c choiceItem) Description() string { return "" }
func (c choiceItem) FilterValue() string { return c.title }

type historyEntry struct {
	Command   string `json:"command"`
	Desc      string `json:"description"`
	Timestamp string `json:"timestamp"`
}

func (h historyEntry) Title() string       { return h.Desc }
func (h historyEntry) Description() string { return fmt.Sprintf("[%s] %s", h.Timestamp, h.Command) }
func (h historyEntry) FilterValue() string { return h.Desc }

// THE ONLY CHANGE IS IN THIS LIST
var (
	scanTypes = []list.Item{
		// --- Basic Discovery ---
		scanType{title: "Ping Scan", description: "Host discovery only, no port scan (no root needed)", commandFmt: "nmap -sn"},
		scanType{title: "Quick Scan", description: "Scans top 1000 TCP ports, fast (no root needed)", commandFmt: "nmap -F"},
		// NEW PRESET:
		scanType{title: "Top Ports on Subnet", description: "Quickly find common open ports across a whole subnet (requires sudo)", commandFmt: "sudo nmap -sS -Pn --top-ports 100 --open"},

		// --- In-Depth Enumeration ---
		scanType{title: "Stealth Scan (SYN)", description: "Standard stealth scan, fast and less detectable (requires sudo)", commandFmt: "sudo nmap -sS"},
		scanType{title: "Service & OS Detection", description: "Detects service versions and OS (may require sudo for OS)", commandFmt: "nmap -sV -O"},
		scanType{title: "Intense Scan", description: "Comprehensive: OS/version detection, scripts, traceroute", commandFmt: "nmap -A"},
		// NEW PRESET:
		scanType{title: "Aggressive \"Get Everything\" Scan", description: "Very noisy! Fast, comprehensive scan for trusted networks", commandFmt: "nmap -A -T5 -Pn --version-intensity 9"},
		// NEW PRESET:
		scanType{title: "SMB/Windows Share Scan", description: "Enumerate SMB shares and check for EternalBlue (requires sudo)", commandFmt: "sudo nmap -p 139,445 -sV --script smb-os-discovery,smb-enum-shares,smb-vuln-ms17-010"},
		scanType{title: "Full TCP Port Scan", description: "Scans all 65535 TCP ports, very slow (requires sudo)", commandFmt: "sudo nmap -p-"},
		scanType{title: "UDP Scan", description: "Scans common UDP ports, very slow (requires sudo)", commandFmt: "sudo nmap -sU --top-ports 20"},

		// --- Vulnerability & Evasion ---
		scanType{title: "Web Server Recon", description: "Finds web servers and runs http-enum, title, ssl-cert scripts", commandFmt: "nmap -p 80,443,8000,8080,8443 -sV --script http-enum,http-title,ssl-cert"},
		// NEW PRESET:
		scanType{title: "Detect WAF/IPS", description: "Tries to detect if a Web Application Firewall is protecting the target", commandFmt: "nmap -p 80,443 --script=http-waf-detect,http-waf-fingerprint"},
		scanType{title: "Quick Vulnerability Scan", description: "Checks for Heartbleed, Poodle, EternalBlue, etc. (requires sudo)", commandFmt: "sudo nmap -sV --script ssl-heartbleed,ssl-poodle,smb-vuln-ms17-010"},
		// NEW PRESET:
		scanType{title: "Safe Scripting Scan", description: "Runs all NSE scripts that are not considered intrusive", commandFmt: "nmap -sV --script=safe"},
		scanType{title: "Firewall Evasion Scan", description: "Uses fragments, decoys, and source port 53 (requires sudo)", commandFmt: "sudo nmap -sS -f --source-port 53 -D RND:3"},

		// --- Interactive & History ---
		scanType{title: "NSE Script Scan (by category)", description: "Run a category of Nmap scripts (e.g., vuln, discovery)", commandFmt: "sudo nmap -sV --script=%s"},
		scanType{title: "Custom Scan", description: "Enter your own nmap flags manually", commandFmt: "nmap %s"},
		scanType{title: "Scan History", description: "View and re-run previous scans", commandFmt: ""},
	}
	nseScripts = []list.Item{
		choiceItem{title: "vuln - Check for known vulnerabilities", value: "vuln"},
		choiceItem{title: "discovery - Actively discover more about the network", value: "discovery"},
		choiceItem{title: "auth - Check for authentication bypasses", value: "auth"},
		choiceItem{title: "default - Nmap's default safe scripts", value: "default"},
	}
	outputFormats = []list.Item{
		choiceItem{title: "Don't Save", value: ""},
		choiceItem{title: "Normal (.txt)", value: "-oN"},
		choiceItem{title: "Grepable (.gnmap)", value: "-oG"},
		choiceItem{title: "XML (.xml)", value: "-oX"},
	}
	timingTemplates = []list.Item{
		choiceItem{title: "T0 (Paranoid)", value: "-T0"},
		choiceItem{title: "T1 (Sneaky)", value: "-T1"},
		choiceItem{title: "T2 (Polite)", value: "-T2"},
		choiceItem{title: "T3 (Normal)", value: "-T3"},
		choiceItem{title: "T4 (Aggressive)", value: "-T4"},
		choiceItem{title: "T5 (Insane)", value: "-T5"},
	}
	verbosityLevels = []list.Item{
		choiceItem{title: "Normal", value: ""},
		choiceItem{title: "Verbose (-v)", value: "-v"},
		choiceItem{title: "Very Verbose (-vv)", value: "-vv"},
	}
)

type model struct {
	state             appState
	stateStack        []appState
	scanList          list.Model
	nseList           list.Model
	saveList          list.Model
	timingList        list.Model
	verbosityList     list.Model
	historyList       list.Model
	targetInput       textinput.Model
	customFlagsInput  textinput.Model
	viewport          viewport.Model
	spinner           spinner.Model
	selectedScan      scanType
	selectedNSE       string
	selectedFormat    string
	selectedTiming    string
	selectedVerbosity string
	target            string
	isTargetFile      bool
	customFlags       string
	command           string
	scanOutput        string
	outputFilename    string
	confirmationMsg   string
	err               error
	terminalWidth     int
	terminalHeight    int
}

func (m *model) pushState(newState appState) {
	m.stateStack = append(m.stateStack, newState)
	m.state = newState
}

func (m *model) popState() {
	if len(m.stateStack) > 1 {
		m.stateStack = m.stateStack[:len(m.stateStack)-1]
		m.state = m.stateStack[len(m.stateStack)-1]
	}
}

type scanOutputMsg string
type scanFinishedMsg struct{ err error }

func getHistoryFilePath() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, historyFilename), nil
}
func loadHistory() []list.Item {
	path, err := getHistoryFilePath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var history []historyEntry
	if err := json.Unmarshal(data, &history); err != nil {
		return nil
	}
	items := make([]list.Item, len(history))
	for i, entry := range history {
		items[i] = entry
	}
	return items
}
func saveToHistory(entry historyEntry) {
	path, err := getHistoryFilePath()
	if err != nil {
		return
	}
	data, err := os.ReadFile(path)
	var history []historyEntry
	if err == nil {
		json.Unmarshal(data, &history)
	}
	history = append([]historyEntry{entry}, history...)
	if len(history) > maxHistoryItems {
		history = history[:maxHistoryItems]
	}
	newData, err := json.MarshalIndent(history, "", "  ")
	if err == nil {
		os.WriteFile(path, newData, 0644)
	}
}
func generateFilename(target, format string) string {
	var ext string
	switch format {
	case "-oN":
		ext = ".txt"
	case "-oG":
		ext = ".gnmap"
	case "-oX":
		ext = ".xml"
	default:
		ext = ".txt"
	}
	safeTarget := strings.ReplaceAll(target, "/", "_")
	timestamp := time.Now().Format("20060102T150405")
	return fmt.Sprintf("nmap_%s_%s%s", safeTarget, timestamp, ext)
}
func checkNmap() tea.Msg {
	_, err := exec.LookPath("nmap")
	if err != nil {
		return scanFinishedMsg{err: fmt.Errorf("nmap command not found. Please install it and make sure it's in your PATH.")}
	}
	return nil
}
func runScan(command string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		parts := strings.Fields(command)
		cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return scanFinishedMsg{err: err}
		}
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			return scanFinishedMsg{err: err}
		}
		go func(reader io.Reader) {
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				p.Send(scanOutputMsg(scanner.Text()))
			}
		}(stdout)
		err = cmd.Wait()
		return scanFinishedMsg{err: err}
	}
}

func initialModel() model {
	scanList := list.New(scanTypes, list.NewDefaultDelegate(), 0, 0)
	scanList.Title = "Choose a Lazy Nmap Scan"
	nseList := list.New(nseScripts, list.NewDefaultDelegate(), 0, 0)
	nseList.Title = "Choose an NSE Script Category"
	saveList := list.New(outputFormats, list.NewDefaultDelegate(), 0, 0)
	saveList.Title = "Save Scan Output?"
	timingList := list.New(timingTemplates, list.NewDefaultDelegate(), 0, 0)
	timingList.Title = "Select a Timing Template"
	timingList.Select(4)
	verbosityList := list.New(verbosityLevels, list.NewDefaultDelegate(), 0, 0)
	verbosityList.Title = "Select Verbosity Level"
	historyList := list.New(loadHistory(), list.NewDefaultDelegate(), 0, 0)
	historyList.Title = "Scan History (Select to re-run)"
	ti := textinput.New()
	ti.Placeholder = "192.168.1.1 or /path/to/targets.txt"
	ti.Focus()
	ti.Width = 60
	cfi := textinput.New()
	cfi.Placeholder = "-A -p 80,443 --open"
	cfi.Width = 60
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = spinnerStyle
	return model{
		state:             stateChoosingScan,
		stateStack:        []appState{stateChoosingScan},
		scanList:          scanList,
		nseList:           nseList,
		saveList:          saveList,
		timingList:        timingList,
		verbosityList:     verbosityList,
		historyList:       historyList,
		targetInput:       ti,
		customFlagsInput:  cfi,
		spinner:           s,
		selectedTiming:    "-T4",
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(checkNmap, m.spinner.Tick)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	if keyMsg, ok := msg.(tea.KeyMsg); ok && keyMsg.String() == "esc" {
		switch m.state {
		case stateScanning, stateShowingResults, stateConfirming:
		default:
			m.popState()
			return m, nil
		}
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.terminalWidth, m.terminalHeight = msg.Width, msg.Height
		h, v := docStyle.GetFrameSize()
		listWidth, listHeight := msg.Width-h, msg.Height-v
		m.scanList.SetSize(listWidth, listHeight)
		m.nseList.SetSize(listWidth, listHeight)
		m.saveList.SetSize(listWidth, listHeight)
		m.timingList.SetSize(listWidth, listHeight)
		m.verbosityList.SetSize(listWidth, listHeight)
		m.historyList.SetSize(listWidth, listHeight)
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - 4
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

		switch m.state {
		case stateChoosingScan:
			if msg.String() == "enter" {
				i, ok := m.scanList.SelectedItem().(scanType)
				if ok {
					m.selectedScan = i
					switch i.title {
					case "Custom Scan":
						m.pushState(stateEnteringCustomFlags)
						m.customFlagsInput.Focus()
					case "NSE Script Scan (by category)":
						m.pushState(stateChoosingNSE)
					case "Scan History":
						m.historyList.SetItems(loadHistory())
						m.pushState(stateShowingHistory)
					default:
						m.pushState(stateEnteringTarget)
						m.targetInput.Focus()
					}
				}
			}
			m.scanList, cmd = m.scanList.Update(msg)
			cmds = append(cmds, cmd)

		case stateEnteringTarget:
			if msg.String() == "enter" && m.targetInput.Value() != "" {
				m.target = m.targetInput.Value()
				m.isTargetFile = false
				if info, err := os.Stat(m.target); err == nil && !info.IsDir() {
					m.isTargetFile = true
				}
				m.pushState(stateChoosingTiming)
			}
			m.targetInput, cmd = m.targetInput.Update(msg)
			cmds = append(cmds, cmd)

		case stateChoosingTiming:
			if msg.String() == "enter" {
				if i, ok := m.timingList.SelectedItem().(choiceItem); ok {
					m.selectedTiming = i.value
					m.pushState(stateChoosingVerbosity)
				}
			}
			m.timingList, cmd = m.timingList.Update(msg)
			cmds = append(cmds, cmd)

		case stateChoosingVerbosity:
			if msg.String() == "enter" {
				if i, ok := m.verbosityList.SelectedItem().(choiceItem); ok {
					m.selectedVerbosity = i.value
					m.pushState(stateSavingOutput)
				}
			}
			m.verbosityList, cmd = m.verbosityList.Update(msg)
			cmds = append(cmds, cmd)

		case stateSavingOutput:
			if msg.String() == "enter" {
				if i, ok := m.saveList.SelectedItem().(choiceItem); ok {
					m.selectedFormat = i.value
					m.command = "" // Clear previous command before confirming
					m.pushState(stateConfirming)
				}
			}
			m.saveList, cmd = m.saveList.Update(msg)
			cmds = append(cmds, cmd)

		case stateShowingHistory:
			if msg.String() == "enter" {
				if i, ok := m.historyList.SelectedItem().(historyEntry); ok {
					m.command = i.Command
					m.pushState(stateConfirming)
				}
			}
			m.historyList, cmd = m.historyList.Update(msg)
			cmds = append(cmds, cmd)

		case stateConfirming:
			if msg.String() == "esc" {
				return initialModel(), nil
			}

			if m.command == "" {
				parts := []string{}
				baseCmd := "nmap"
				if strings.HasPrefix(m.selectedScan.commandFmt, "sudo") {
					baseCmd = "sudo nmap"
				}

				var mainFlags, targetPart string
				switch m.selectedScan.title {
				case "Custom Scan":
					mainFlags = m.customFlags
				case "NSE Script Scan (by category)":
					mainFlags = fmt.Sprintf(m.selectedScan.commandFmt, m.selectedNSE)
					mainFlags = strings.TrimSpace(strings.Replace(mainFlags, "sudo nmap", "", 1))
				default:
					mainFlags = strings.TrimSpace(strings.Replace(m.selectedScan.commandFmt, "nmap", "", 1))
					mainFlags = strings.TrimSpace(strings.Replace(mainFlags, "sudo", "", 1))
				}

				if m.isTargetFile {
					targetPart = "-iL " + m.target
				} else {
					targetPart = m.target
				}

				parts = append(parts, baseCmd)
				if m.selectedTiming != "" {
					parts = append(parts, m.selectedTiming)
				}
				if m.selectedVerbosity != "" {
					parts = append(parts, m.selectedVerbosity)
				}
				if mainFlags != "" {
					parts = append(parts, mainFlags)
				}
				parts = append(parts, targetPart)

				if m.selectedFormat != "" {
					m.outputFilename = generateFilename(m.target, m.selectedFormat)
					parts = append(parts, m.selectedFormat, m.outputFilename)
				}
				m.command = strings.Join(parts, " ")
			}

			switch strings.ToLower(msg.String()) {
			case "y", "enter":
				if m.selectedScan.title != "Scan History" {
					desc := fmt.Sprintf("%s on %s", m.selectedScan.title, m.target)
					if m.selectedScan.title == "Custom Scan" {
						desc = fmt.Sprintf("Custom Scan (%s) on %s", m.customFlags, m.target)
					}
					saveToHistory(historyEntry{
						Command:   m.command,
						Desc:      desc,
						Timestamp: time.Now().Format("2006-01-02 15:04"),
					})
				}
				m.pushState(stateScanning)
				return m, runScan(m.command)
			case "c":
				clipboard.WriteAll(m.command)
				m.confirmationMsg = "Command copied to clipboard!"
				return m, nil
			}

		case stateShowingResults:
			if msg.String() == "enter" || msg.String() == "q" {
				return initialModel(), nil
			}
			m.viewport, cmd = m.viewport.Update(msg)
			cmds = append(cmds, cmd)

		case stateEnteringCustomFlags:
			if msg.String() == "enter" && m.customFlagsInput.Value() != "" {
				m.customFlags = m.customFlagsInput.Value()
				m.pushState(stateEnteringTarget)
				m.targetInput.Focus()
			}
			m.customFlagsInput, cmd = m.customFlagsInput.Update(msg)
			cmds = append(cmds, cmd)

		case stateChoosingNSE:
			if msg.String() == "enter" {
				if i, ok := m.nseList.SelectedItem().(choiceItem); ok {
					m.selectedNSE = i.value
					m.pushState(stateEnteringTarget)
					m.targetInput.Focus()
				}
			}
			m.nseList, cmd = m.nseList.Update(msg)
			cmds = append(cmds, cmd)

		case stateScanning:
			m.spinner, cmd = m.spinner.Update(msg)
			cmds = append(cmds, cmd)
		}

	case scanOutputMsg:
		m.scanOutput += string(msg) + "\n"
		m.viewport.SetContent(m.scanOutput)
		m.viewport.GotoBottom()
		return m, nil

	case scanFinishedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.scanOutput += "\n\n" + errorStyle.Render("Error: "+msg.err.Error())
		}
		if m.outputFilename != "" && msg.err == nil {
			m.scanOutput += "\n\n" + confirmationStyle.Render(fmt.Sprintf("✔ Scan output saved to %s", m.outputFilename))
		}
		m.viewport.SetContent(m.scanOutput)
		m.pushState(stateShowingResults)
		return m, nil

	default:
		if m.state == stateScanning {
			m.spinner, cmd = m.spinner.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	if m.err != nil {
		return docStyle.Render(errorStyle.Render(fmt.Sprintf("An error occurred: %v", m.err)) + "\n\nPress any key to exit.")
	}

	helpFooter := helpStyle.Render("\n\n(press esc to go back)")

	switch m.state {
	case stateChoosingScan:
		return docStyle.Render(m.scanList.View())
	case stateEnteringTarget:
		s := titleStyle.Render("Enter Target or Target File") +
			"\nYou can enter an IP, hostname, or a file path (e.g., ./targets.txt)\n\n" +
			m.targetInput.View() +
			helpStyle.Render("\n\n(press enter to continue)") + helpFooter
		return docStyle.Render(s)
	case stateChoosingTiming, stateChoosingVerbosity, stateSavingOutput, stateShowingHistory, stateChoosingNSE:
		var listView list.Model
		switch m.state {
		case stateChoosingTiming:
			listView = m.timingList
		case stateChoosingVerbosity:
			listView = m.verbosityList
		case stateSavingOutput:
			listView = m.saveList
		case stateShowingHistory:
			listView = m.historyList
		case stateChoosingNSE:
			listView = m.nseList
		}
		return docStyle.Render(listView.View() + helpFooter)
	case stateEnteringCustomFlags:
		return docStyle.Render(titleStyle.Render("Enter Custom Nmap Flags") + "\n\n" + m.customFlagsInput.View() + helpStyle.Render("\n\n(press enter to continue)") + helpFooter)

	case stateConfirming:
		confirmView := titleStyle.Render("Confirm Scan") +
			fmt.Sprintf("\n\n%s\n%s", promptStyle.Render("The following command will be executed:"), cmdStyle.Render(m.command))
		if m.confirmationMsg != "" {
			confirmView += "\n\n" + confirmationStyle.Render(m.confirmationMsg)
		}
		confirmView += helpStyle.Render("\n\nAre you sure? (y/N)  |  (c)opy command  |  (esc)ancel to start over")
		return docStyle.Render(confirmView)

	case stateScanning:
		header := viewportHeader.Width(m.terminalWidth).Render(fmt.Sprintf("%s Scanning %s...", m.spinner.View(), m.target))
		footer := viewportFooter.Width(m.terminalWidth).Render("Scan in progress... (Ctrl+C to abort)")
		return fmt.Sprintf("%s\n%s\n%s", header, m.viewport.View(), footer)
	case stateShowingResults:
		headerText := fmt.Sprintf("Scan Complete: %s", m.target)
		header := viewportHeader.Width(m.terminalWidth).Render(headerText)
		footer := viewportFooter.Width(m.terminalWidth).Render("Scroll with ↑/↓. Press Enter or 'q' for a new scan.")
		return fmt.Sprintf("%s\n%s\n%s", header, m.viewport.View(), footer)
	default:
		return "Unknown state."
	}
}

var p *tea.Program

func main() {
	time.Sleep(100 * time.Millisecond)
	m := initialModel()
	p = tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}
