package describe

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Binject/debug/pe"
	"github.com/redt1de/MaldevEDR/pkg/util"
)

type DescribeResult struct {
	File          string
	MD5Hash       string
	SHA256Hash    string
	Arch          string
	Timestamp     string
	Size          string
	Managed       bool
	NetCLRVersion string
	Signed        bool
	Certificates  string
	Imports       []string
	Exports       []string
}

func Analyze(filePath string) (*DescribeResult, error) {
	var ret DescribeResult
	if filePath == "" {
		return nil, fmt.Errorf("please provide a file to analyze")

	}
	peFile, err := pe.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer peFile.Close()

	raw, _ := peFile.Bytes()
	hashMD5 := md5.New()
	if _, err := io.Copy(hashMD5, bytes.NewReader(raw)); err != nil {
		return nil, err
	}
	md5Str := hex.EncodeToString(hashMD5.Sum(nil)[:16])

	hashSHA := sha256.New()
	if _, err := io.Copy(hashSHA, bytes.NewReader(raw)); err != nil {
		return nil, err
	}
	shaStr := hex.EncodeToString(hashSHA.Sum(nil)[:32])

	// localLogger.Write("")
	// localLogger.Write("File         :", filepath.Base(filePath))
	ret.File = filepath.Base(filePath)
	// localLogger.Write("MD5 hash     :", md5Str)
	ret.MD5Hash = md5Str
	// localLogger.Write("SHA256 hash  :", shaStr)
	ret.SHA256Hash = shaStr
	// localLogger.Write("Architecture :", getArch(peFile))
	ret.Arch = getArch(peFile)
	// localLogger.Write("Timestamp    :", getTimestamp(peFile))
	ret.Timestamp = getTimestamp(peFile)

	ret.Size = util.FileSize(len(raw))
	// localLogger.Write("Managed      :", peFile.IsManaged())
	ret.Managed = peFile.IsManaged()
	if peFile.IsManaged() {
		// localLogger.Write(".NET CLR Version  :", peFile.NetCLRVersion())
		ret.NetCLRVersion = peFile.NetCLRVersion()
	}
	ret.Signed, ret.Certificates = getCerts(filePath)
	ret.Imports = getImports(peFile)
	ret.Exports = getExports(peFile)

	// if dostrings {
	// 	doStrings(filePath)
	// }
	return &ret, nil
}

// func doStrings(filePath string) {
// 	localLogger.Write("Running strings.exe via live.sysinternals.com...")
// 	outname := filepath.Base(filePath) + "_strings.txt"
// 	cmd := exec.Command("cmd.exe", "/c", "\\\\live.sysinternals.com@SSL\\DavWWWRoot\\strings.exe", "-accepteula", "-n", "7", filePath)
// 	var outb, errb bytes.Buffer
// 	cmd.Stdout = &outb
// 	cmd.Stderr = &errb
// 	err := cmd.Run()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	if outb.Len() > 0 {
// 		err := os.WriteFile(outname, outb.Bytes(), 0644)
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 	}
// }

func getImports(peFile *pe.File) []string {
	var ret []string
	symbs, _ := peFile.ImportedSymbols()
	for _, imp := range symbs {
		// localLogger.Write("       ", imp)
		tmp := strings.Trim(imp, " ")
		if tmp != "" {
			ret = append(ret, tmp)
		}
	}
	return ret

}

func getExports(peFile *pe.File) []string {
	var ret []string
	symbs, _ := peFile.Exports()
	for _, imp := range symbs {
		// localLogger.Write("       ", imp)
		tmp := strings.Trim(imp.Name, " ")
		if tmp != "" {
			ret = append(ret, tmp)
		}
	}
	return ret
}

func getArch(peFile *pe.File) string {
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x64_86"
	default:
		return "Unknown"
	}
}

func getTimestamp(peFile *pe.File) string {
	stringUnix := fmt.Sprintf("%d", peFile.TimeDateStamp)
	intUnix, err := strconv.ParseInt(stringUnix, 10, 64)
	if err != nil {
		log.Fatal(err)
	}
	myTime := time.Unix(intUnix, 0)
	return myTime.String()
}

func CapUint32(v uint32, max uint32) uint32 {
	if v > max {
		return max
	}
	return v
}

func getCerts(filePath string) (bool, string) {
	cmd := exec.Command("powershell", "-Command", "Get-AuthenticodeSignature '"+filePath+"' | Format-List *")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return false, ""
	}
	output := out.String()
	output = strings.ReplaceAll(output, "\r", "")
	re := regexp.MustCompile(` {2,}`)
	output = re.ReplaceAllString(output, " ")
	output = strings.ReplaceAll(output, "\t", "")
	output = strings.ReplaceAll(output, "\n \n", "\n")
	output = strings.ReplaceAll(output, "\n\n", "\n")

	output = strings.ReplaceAll(output, "[", "")
	output = strings.ReplaceAll(output, "]", ":")
	output = strings.ReplaceAll(output, ":\n", ":")
	output = strings.ReplaceAll(output, " : Subject:", ":\n\t\tSubject:")
	output = strings.ReplaceAll(output, "\n ", "\n\t\t")
	re2 := regexp.MustCompile(`(?m)^([A-Z])`)
	output = re2.ReplaceAllString(output, "\t$1")
	if len(output) > 0 && !strings.Contains(output, "NotSigned") {
		return true, output
	}
	return false, ""

}
