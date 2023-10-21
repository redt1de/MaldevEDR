package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/redt1de/MaldevEDR/pkg/describe"
	"github.com/redt1de/MaldevEDR/pkg/entropy"
	"github.com/redt1de/MaldevEDR/pkg/threatcheck"
	"github.com/redt1de/MaldevEDR/pkg/util"
	"github.com/theckman/yacspin"
)

func printf(a string, b ...any) { fmt.Printf(a, b...) }

const (
	RedColor     = "\033[1;31m"
	GreenColor   = "\033[1;32m"
	YellowColor  = "\033[1;33m"
	BlueColor    = "\033[1;34m"
	MagentaColor = "\033[1;35m"
	CyanColor    = "\033[1;36m"
	Reset        = "\033[0m"
)

var spinCfg = yacspin.Config{
	Frequency:       100 * time.Millisecond,
	CharSet:         yacspin.CharSets[52],
	Suffix:          " ",
	SuffixAutoColon: true,
	ColorAll:        true,
	Colors:          []string{"fgYellow"},
	Message:         "Done",
	StopCharacter:   "✓",
	StopColors:      []string{"fgGreen"},
}

type Result struct {
	File        string
	PeInfo      describe.DescribeResult
	Entropy     entropy.EntropyResult
	ThreatCheck threatcheck.DefenderScanResult
	Verbose     bool
}

func main() {
	var name string
	var skipTC, verbose bool
	var result Result
	flag.StringVar(&name, "test", "", "test param for testing test stuff, test")
	flag.BoolVar(&skipTC, "no-threatcheck", false, "skip threatcheck")
	flag.BoolVar(&verbose, "verbose", false, "verbose output")
	flag.Parse()

	result.File = name

	spinner, _ := yacspin.New(spinCfg)
	spinner.Start()

	// describe
	spinner.Message("Gathering info on file")
	descResult, err := describe.Analyze(result.File)
	if err != nil {
		panic(err)
	}
	result.PeInfo = *descResult

	// entropy
	spinner.Message("Perfoming entropy analysis on file")
	entropyResult, err := entropy.Analyze(result.File)
	if err != nil {
		panic(err)
	}
	result.Entropy = *entropyResult

	// threatcheck
	if !skipTC {
		spinner.Message("Perfoming static signature analysis on file")
		tc := threatcheck.NewDefender()
		tcResult, err := tc.AnalyzeFile(result.File)
		if err != nil {
			panic(err)
		}
		result.ThreatCheck = *tcResult
	}

	// done
	err = spinner.Stop()
	PrintResult(&result)
}

// print details of result
func PrintResult(r *Result) {
	println("\n############################### PE Info ###############################")
	printf("File         : %s\n", r.PeInfo.File)
	printf("MD5          : %s\n", r.PeInfo.MD5Hash)
	printf("SHA256       : %s\n", r.PeInfo.SHA256Hash)
	printf("Arch         : %s\n", r.PeInfo.Arch)
	printf("Timestamp    : %s\n", r.PeInfo.Timestamp)
	printf("Size         : %s\n", r.PeInfo.Size)
	printf("Managed      : %t\n", r.PeInfo.Managed)
	if r.PeInfo.Managed {
		printf("\tCLR Version: %s\n", r.PeInfo.NetCLRVersion)
	}
	if !r.PeInfo.Signed {
		printf("Signed       : %s%t%s\n", RedColor, r.PeInfo.Signed, Reset)
	} else {
		printf("Signed       : %t\n", r.PeInfo.Signed)
		printf("Certificates:\n %s\n", r.PeInfo.Certificates)
	}
	printf("Imports      : %d\n", len(r.PeInfo.Imports))
	if r.Verbose {
		for _, imp := range r.PeInfo.Imports {
			printf("\t%s\n", imp)
		}
	}
	printf("Exports      : %d\n", len(r.PeInfo.Exports))
	if r.Verbose {
		for _, exp := range r.PeInfo.Exports {
			printf("\t%s\n", exp)
		}
	}

	println("\n############################### Entropy ###############################")
	longest := 0
	for _, section := range r.Entropy.Sections {
		if len(section.Name) > longest {
			longest = len(section.Name)
		}
	}

	for _, section := range r.Entropy.Sections {
		pad := ""
		for i := 0; i < longest-len(section.Name); i++ {
			pad += " "
		}
		if section.Entropy > 7.0 {
			printf("%s%s  : %s%.04f%s (%s)\n", section.Name, pad, RedColor, section.Entropy, Reset, util.FileSize(section.Size))
		}
		printf("%s%s  : %.04f (%s)\n", section.Name, pad, section.Entropy, util.FileSize(section.Size))
	}
	pad := ""
	for i := 0; i < longest-len("Total"); i++ {
		pad += " "
	}
	if r.Entropy.TotalEntropy > 7.0 {
		printf("Total%s  : %s%.04f%s\n", pad, RedColor, r.Entropy.TotalEntropy, Reset)
	} else {
		printf("Total%s  : %.04f\n", pad, r.Entropy.TotalEntropy)
	}

	println("\n############################# Threat Check #############################")
	if r.ThreatCheck.Threat {
		printf("Threat Found: %s%s%s\n", RedColor, r.ThreatCheck.Signature, Reset)
		printf("Start of Bad Bytes At: 0x%x\n", r.ThreatCheck.Offset)
		println(util.HexDump(r.ThreatCheck.BadBytes, int(r.ThreatCheck.Offset)))
	} else {
		println("No threat found!")
	}
}
