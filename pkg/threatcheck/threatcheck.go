package threatcheck

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	NoThreatFound ScanResult = iota
	ThreatFound
	FileNotFound
	Timeout
	Error
)

var badBytes []byte

type DefenderScanResult struct {
	Threat    bool
	Result    ScanResult
	Signature string
	BadBytes  []byte
	Offset    uint64
}

type ScanResult int

type Scanner interface {
	ScanFile(file string, getsig bool) DefenderScanResult
}

type Defender struct {
	// Logger    *util.ConsoleLogger
	FileBytes []byte
	FilePath  string
	Malicious bool
	Complete  bool
}

func NewDefender() *Defender {
	return &Defender{}
}

func (d *Defender) AnalyzeFile(fPath string) (*DefenderScanResult, error) {
	var ret DefenderScanResult
	file, err := os.ReadFile(fPath)
	if err != nil {
		return nil, fmt.Errorf("failed read mal file: %w", err)
	}
	d.FileBytes = file
	if _, err := os.Stat("C:\\Temp"); os.IsNotExist(err) {
		// d.Logger.WriteDebug(`C:\Temp doesn't exist. Creating it...`)
		os.Mkdir("C:\\Temp", os.ModePerm)
	}

	// fmt.Printf("Performing static analysis via MpCmdRun.exe...\n")

	d.FilePath = filepath.Join("C:\\Temp", "file.exe")
	ioutil.WriteFile(d.FilePath, d.FileBytes, os.ModePerm)

	status := d.ScanFile(d.FilePath, true)
	ret.Result = status.Result

	if status.Result == NoThreatFound {
		// d.Logger.WriteSuccess("No threat found!")
		return &ret, nil
	}

	ret.Signature = status.Signature
	// fmt.Printf("File identified as: %s\n", status.Signature)

	ret.Threat = true

	// d.Logger.WriteDebug(fmt.Sprintf("Target file size: %d bytes", len(d.FileBytes)))

	splitArray := make([]byte, len(d.FileBytes)/2)
	copy(splitArray, d.FileBytes[:len(d.FileBytes)/2])
	lastgood := 0
	for {
		// d.Logger.WriteDebug("Testing " + strconv.Itoa(len(splitArray)) + " bytes")
		// File.WriteAllBytes(FilePath, splitArray);
		err := ioutil.WriteFile(d.FilePath, splitArray, os.ModePerm)
		if err != nil {
			// d.Logger.WriteFatal("threacheck loop:", err)
			// os.Exit(1)
			return nil, fmt.Errorf("threacheck loop: %w", err)
		}
		status = d.ScanFile(d.FilePath, false)

		if status.Result == ThreatFound {
			// d.Logger.WriteDebug("Threat found, splitting")
			tmpArray, tmpOffset := d.HalfSplitter(splitArray, lastgood)
			ret.Offset = tmpOffset
			splitArray = make([]byte, len(tmpArray))
			copy(splitArray, tmpArray)

		} else if status.Result == NoThreatFound {
			// d.Logger.WriteDebug("No threat found, increasing size")
			lastgood = len(splitArray)
			tmpArray := d.Overshot(d.FileBytes, len(splitArray))
			splitArray = make([]byte, len(tmpArray))
			copy(splitArray, tmpArray)
		} else {
			// d.Logger.WriteFatal("threacheck loop: running Defender failed")
			return nil, fmt.Errorf("threacheck loop: running Defender failed")
		}

		if d.Complete {
			break
		}
	}
	ret.BadBytes = make([]byte, len(badBytes))
	copy(ret.BadBytes, badBytes)
	return &ret, nil

}

func (d *Defender) ScanFile(file string, getsig bool) DefenderScanResult {
	result := DefenderScanResult{}

	if _, err := os.Stat(file); os.IsNotExist(err) {
		result.Result = FileNotFound
		return result
	}

	var bout, berr bytes.Buffer
	mpcmdrun := exec.Command("C:\\Program Files\\Windows Defender\\MpCmdRun.exe")
	mpcmdrun.Args = append(mpcmdrun.Args, "-Scan", "-ScanType", "3", "-File", file, "-DisableRemediation", "-Trace", "-Level", "0x10")
	mpcmdrun.Stdout = &bout
	mpcmdrun.Stderr = &berr

	mpcmdrun.Run()

	if getsig {
		output := bout.String()
		sigName := parseSignatureName(output)
		result.Signature = sigName
	}

	switch mpcmdrun.ProcessState.ExitCode() {
	case 0:
		result.Result = NoThreatFound
	case 2:
		result.Result = ThreatFound
	default:
		result.Result = Error
	}

	return result
}

func parseSignatureName(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.ReplaceAll(line, " ", "")
		if strings.Contains(line, "Threat:") {
			sig := strings.ReplaceAll(line, "Threat:", "")
			sig = strings.ReplaceAll(sig, "\r", "")
			sig = strings.ReplaceAll(sig, "\n", "")
			return sig
		}
	}
	return ""
}

func (d *Defender) HalfSplitter(originalArray []byte, lastGood int) ([]byte, uint64) {
	retOffset := uint64(0)
	splitArray := make([]byte, (len(originalArray)-lastGood)/2+lastGood)

	if len(originalArray) == len(splitArray)+1 {
		// fmt.Printf("Identified end of bad bytes at offset 0x%X\n", len(originalArray))
		// d.Logger.WriteInfo(msg)
		retOffset = uint64(len(originalArray))

		offendingBytes := make([]byte, 256)
		if len(originalArray) < 256 {
			offendingBytes = make([]byte, len(originalArray))
			copy(offendingBytes, originalArray)
		} else {
			copy(offendingBytes, originalArray[len(originalArray)-256:])
		}

		// fmt.Println(hex.Dump(offendingBytes))
		badBytes = append(badBytes, offendingBytes...)
		// copy(badBytes, offendingBytes)
		d.Complete = true
	}

	copy(splitArray, originalArray[:len(splitArray)])
	return splitArray, retOffset
}

func (d *Defender) Overshot(originalArray []byte, splitArraySize int) []byte {
	newSize := (len(originalArray)-splitArraySize)/2 + splitArraySize

	if newSize == len(originalArray)-1 {
		d.Complete = true

		if d.Malicious {
			fmt.Println("File is malicious, but couldn't identify bad bytes")
		}
	}

	newArray := make([]byte, newSize)
	copy(newArray, originalArray[:newSize])

	return newArray
}
