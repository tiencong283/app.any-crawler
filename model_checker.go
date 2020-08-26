package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ToJson serializes the object into json format
func ToJson(v interface{}) string {
	bytes, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err.Error()
	}
	return string(bytes)
}

type ProcessTree struct {
	Root       *ProcessNode
	NodesByPid map[int]*ProcessNode
	NodesById  map[string]*ProcessNode
}

func NewProcessTree() *ProcessTree {
	return &ProcessTree{
		NodesByPid: make(map[int]*ProcessNode),
		NodesById:  make(map[string]*ProcessNode),
	}
}

func LoadProcessTree(fileAt string) (*ProcessTree, *ProcessData, error) {
	file, err := os.Open(fileAt)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	var procData *ProcessData
	if err := json.Unmarshal(bytes, &procData); err != nil {
		return nil, nil, err
	}

	procTree := NewProcessTree()
	var mainProc *Process
	for i := 0; i < len(procData.Processes); i++ {
		if procData.Processes[i].ProcessType == "Main process" {
			mainProc = procData.Processes[i]
			break
		}
	}
	if mainProc == nil {
		return nil, procData, errors.New("corrupted data, cannot find \"Main process\" process")
	}
	proc := NewProcessNode(mainProc)
	procTree.Root = proc
	procTree.AddProc(proc)

	for _, proc := range procData.Processes[1:] {
		procNode := NewProcessNode(proc)
		procTree.AddProc(procNode)
		if parentNode, ok := procTree.NodesByPid[procNode.ParentPID]; ok {
			parentNode.Children = append(parentNode.Children, procNode)
		}
	}

	for _, incident := range procData.Incidents {
		if len(incident.MitreAttacks) == 0 {
			continue
		}
		if procNode, ok := procTree.NodesById[incident.ProcessOID]; ok {
			for _, techId := range incident.MitreAttacks {
				procNode.Techniques[techId] = true
			}
		}
	}
	procTree.Refactor()
	return procTree, procData, nil
}

func (procTree *ProcessTree) AddProc(proc *ProcessNode) {
	procTree.NodesByPid[proc.ProcessID] = proc
	procTree.NodesById[proc.OID] = proc
}

func (procTree *ProcessTree) Refactor() {
	for _, procNode := range procTree.NodesByPid {
		sort.Slice(procNode.Children, func(i, j int) bool {
			return procNode.Children[i].CreationTimestamp > procNode.Children[j].CreationTimestamp
		})
	}
}

func (procTree *ProcessTree) DepthFirstSearch() []*ProcessNode {
	flatTree := make([]*ProcessNode, 0, len(procTree.NodesByPid))
	stack := make([]*ProcessNode, 1, len(procTree.NodesByPid))
	stack[0] = procTree.Root

	var procNode *ProcessNode
	for len(stack) > 0 {
		procNode, stack = stack[len(stack)-1], stack[:len(stack)-1]
		flatTree = append(flatTree, procNode)
		for i := len(procNode.Children) - 1; i >= 0; i-- {
			stack = append(stack, procNode.Children[i])
		}
	}
	return flatTree
}

func (procTree *ProcessTree) CompareTo(another *ProcessTree) float64 {
	flatTreeA := procTree.DepthFirstSearch()
	flatTreeB := another.DepthFirstSearch()

	if len(flatTreeA) != len(flatTreeB) { // only consider two equal tree
		return 0
	}
	// product/summation operator
	var ans float64
	for i := 0; i < len(flatTreeA); i++ {
		ans += flatTreeA[i].compareTo(flatTreeB[i])
	}
	return ans / float64(len(flatTreeA))
}

type ProcessNode struct {
	*Process
	Children   []*ProcessNode
	Parent     *ProcessNode
	Techniques map[string]bool
}

func NewProcessNode(proc *Process) *ProcessNode {
	return &ProcessNode{
		Process:    proc,
		Children:   make([]*ProcessNode, 0),
		Techniques: make(map[string]bool),
	}
}

func (procNode *ProcessNode) addChild(child *ProcessNode) {
	// future: should change Children to linked list
	procNode.Children = append(procNode.Children, child)
}

func (procNode *ProcessNode) compareTo(another *ProcessNode) float64 {
	// should web consider the process name, image and commandline or only consider its techniques

	if len(procNode.Techniques) == 0 { // no technique case
		if strings.EqualFold(GetImageName(procNode.Image), GetImageName(another.Image)) {
			return 1
		}
		return 0
	}

	numOfMatchedTechIds := 0
	for techId := range another.Techniques {
		if procNode.Techniques[techId] {
			numOfMatchedTechIds++
		}
	}
	return float64(numOfMatchedTechIds) / float64(len(procNode.Techniques))
}

var malwareTag string
var isCrawler bool
var isEvaluator bool

func init() {
	flag.BoolVar(&isCrawler, "c", false, "crawling tasks from app.any.run")
	flag.BoolVar(&isEvaluator, "e", false, "grouping tasks by its similarity")
}

func checkWithProfile(profile *ProcessTree, profileData *ProcessData, procTrees map[*ProcessData]*ProcessTree,
	deleted bool) ([]float64,
	[]*ProcessData) {
	results := make([]float64, 0)
	similars := make([]*ProcessData, 0)

	for procData, procTree := range procTrees {
		if profileData.UUID == procData.UUID {
			continue
		}
		result := profile.CompareTo(procTree)
		if result > 0.5 {
			results = append(results, result)
			similars = append(similars, procData)
			if deleted {
				delete(procTrees, procData)
			}
		}
	}
	return results, similars
}

func printResult(profileData *ProcessData, dataSize int, results []float64, similars []*ProcessData) {
	log.Println()
	log.Printf("[*] coverage: %.2f%%, md5: %s, uuid: %s, profile: %s\n", float64(len(results))*100/float64(dataSize),
		profileData.Md5, profileData.UUID, profileData.Name)
	for i := 0; i < len(results); i++ {
		procData := similars[i]
		result := results[i]
		log.Printf("P: %.2f, md5: %s, uuid: %s, name: %s\n", result, procData.Md5, procData.UUID, procData.Name)
	}
}

func main() {
	flag.Parse()
	switch {
	case isCrawler:
		if flag.NArg() < 2 {
			fmt.Printf("Usage: %s -c <Malware Tag> <Task Index Index> <Number of Tasks>\n", os.Args[0])
			os.Exit(0)
		}
		malwareTag = flag.Args()[0]
		taskIndex, _ := strconv.Atoi(flag.Args()[1])
		numOfTasks, _ := strconv.Atoi(flag.Args()[2])
		crawlTasks(malwareTag, taskIndex, numOfTasks)
	case isEvaluator:
		if flag.NArg() < 1 {
			fmt.Printf("Usage: %s -e <Malware Tag> [Task File Name]\n", os.Args[0])
			os.Exit(0)
		}
		malwareTag = flag.Args()[0]
		var profileAt string
		if flag.NArg() >= 2 {
			profileAt = flag.Args()[1]
		}

		// loading process tree data
		files, err := ioutil.ReadDir(malwareTag)
		if err != nil {
			log.Fatal(err)
		}
		dataSize := len(files)
		log.Printf("considering %d tasks\n", dataSize)
		procTrees := make(map[*ProcessData]*ProcessTree)
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
				procTree, procData, err := LoadProcessTree(fmt.Sprintf("%s/%s", malwareTag, file.Name()))
				if err != nil {
					log.Printf("Warn: cannot load process tree model at %s, %s", file.Name(), err)
					continue
				}
				procTrees[procData] = procTree
			}
		}
		if profileAt != "" {
			profile, profileData, err := LoadProcessTree(fmt.Sprintf("%s/%s.json", malwareTag, profileAt))
			if err != nil {
				log.Fatal(err)
			}
			results, similars := checkWithProfile(profile, profileData, procTrees, false)
			printResult(profileData, dataSize, results, similars)
		} else {
			var totalCoverage float64
			var counter int
			for procData, procTree := range procTrees {
				results, similars := checkWithProfile(procTree, procData, procTrees, true)
				if len(results) == 0 {
					continue
				}
				printResult(procData, dataSize, results, similars)
				totalCoverage += float64(len(results)) / float64(dataSize)
				counter++
			}
			log.Printf("[*] total effective profile: %d/%d, total coverage: %.2f %%\n", counter, dataSize, totalCoverage*100)
		}
	default:
		flag.Usage()
		os.Exit(0)
	}
}
