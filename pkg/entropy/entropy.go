package entropy

import (
	"fmt"
	"math"

	"github.com/Binject/debug/pe"
)

type EntropyResult struct {
	TotalEntropy float64
	Sections     []Section
}

type Section struct {
	Name    string
	Size    int
	Entropy float64
}

func Analyze(filePath string) (*EntropyResult, error) {
	var ret EntropyResult
	if filePath == "" {
		return nil, fmt.Errorf("please provide a file to analyze")
	}

	peFile, err := pe.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer peFile.Close()

	raw, _ := peFile.Bytes()

	// fmt.Println("")
	// fmt.Println("File         :", filepath.Base(filePath))
	// fmt.Println("Total Entropy:", getEntropy(raw))
	ret.TotalEntropy = getEntropy(raw)

	// fmt.Println("Sections:")
	for _, section := range peFile.Sections {

		// fmt.Println("\tName   :", section.Name)
		// fmt.Println("\tSize   :", section.Size)
		data, _ := section.Data()
		// fmt.Println("\tEntropy:", getEntropy(data))
		// println()
		ret.Sections = append(ret.Sections, Section{
			Name:    section.Name,
			Size:    int(section.Size),
			Entropy: getEntropy(data),
		})

	}
	return &ret, nil
}

func getEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	occurrences := make(map[byte]int)
	for _, b := range data {
		occurrences[b]++
	}

	var entropy float64 = 0
	for _, x := range occurrences {
		p_x := float64(x) / float64(len(data))
		entropy -= p_x * math.Log2(p_x)
	}

	return entropy
}
