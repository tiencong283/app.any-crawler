package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

var (
	SupportedTaskExtensions = map[string]string{
		"PE EXE":           "0",
		"Microsoft Office": "6",
	}
	SupportedTaskDetections = map[string]int{
		"No threats": 0,
		"Suspicious": 1,
		"Malicious":  2,
	}
)

type (
	PublicTasksCounterResult struct {
		Msg    string `json:"msg"`
		ID     string `json:"id"`
		Result struct {
			Count uint `json:"count"`
		} `json:"result"`
	}
	// This is not a complete structure because many ignored fields are verbose or just used internally by App.Any.Run
	// runType can be "file", "url", "download"
	RawTask struct {
		Msg        string `json:"msg"`
		Collection string `json:"collection"`
		ID         string `json:"id"`
		Fields     struct {
			Significant bool `json:"significant"`
			Public      struct {
				Objects struct {
					MainObject struct {
						Names struct {
							Basename   string `json:"basename"`
							Real       string `json:"real"`
							URL        string `json:"url"`
							Location   string `json:"location"`
							NeedRename bool   `json:"need_rename"`
						} `json:"names"`
						Hashes struct {
							Ssdeep   string `json:"ssdeep"`
							HeadHash string `json:"head_hash"`
							Sha256   string `json:"sha256"`
							Sha1     string `json:"sha1"`
							Md5      string `json:"md5"`
						} `json:"hashes"`
						Info struct {
							Cmd  string `json:"cmd"`
							Meta struct {
								File string `json:"file"`
								Mime string `json:"mime"`
							} `json:"meta"`
						} `json:"info"`
						Content struct {
							Ext string `json:"ext"`
						} `json:"content"`
						Type string `json:"type"`
					} `json:"mainObject"`
					RunType string `json:"runType"`
				} `json:"objects"`
			} `json:"public"`
			Tags   []string `json:"tags"`
			Scores struct {
				Verdict struct {
					ThreatLevel int    `json:"threat_level"`
					Text        string `json:"text"`
				} `json:"verdict"`
			} `json:"scores"`
			UUID string `json:"uuid"`
		} `json:"fields"`
	}

	RawProcess struct {
		Msg        string `json:"msg"`
		Collection string `json:"collection"`
		ID         string `json:"id"`
		Fields     struct {
			Ms   int `json:"ms"`
			Tl   int `json:"tl"`
			Rb   int `json:"rb"`
			Pid  int `json:"pid"`
			Task struct {
				Type  string `json:"$type"`
				Value string `json:"$value"`
			} `json:"task"`
			ParentPID  int         `json:"parentPID"`
			ParentTID  int         `json:"parentTID"`
			RealPPID   int         `json:"_realPPID"`
			RealPSTART int64       `json:"_realPSTART"`
			RealSTART  int64       `json:"_realSTART"`
			Cmd        string      `json:"cmd"`
			Resolved   interface{} `json:"resolved"`
			Exit       struct {
				Code int `json:"code"`
				How  int `json:"how"`
			} `json:"exit"`
			HeadHash string `json:"head_hash"`
			Times    struct {
				Created struct {
					Date int64 `json:"$date"`
				} `json:"created"`
				Closed struct {
					Date int64 `json:"$date"`
				} `json:"closed"`
			} `json:"times"`
			User struct {
				Name string `json:"name"`
				Sid  string `json:"sid"`
				Il   string `json:"il"`
			} `json:"user"`
			Version struct {
				Description string `json:"description"`
				Company     string `json:"company"`
				Version     string `json:"version"`
			} `json:"version"`
			EventsCounters struct {
				Raw struct {
					Registry int `json:"registry"`
					Files    int `json:"files"`
					Modules  int `json:"modules"`
				} `json:"raw"`
				DroppedFiles int `json:"dropped_files"`
				DebugStrings int `json:"debug_strings"`
				Network      int `json:"network"`
			} `json:"events_counters"`
			Image     string `json:"image"`
			ImageUp   string `json:"imageUp"`
			Important bool   `json:"important"`
			Scores    struct {
				Specs struct {
					Network           bool `json:"network"`
					UacRequest        bool `json:"uac_request"`
					KnownThreat       bool `json:"known_threat"`
					Injects           bool `json:"injects"`
					NetworkLoader     bool `json:"network_loader"`
					ServiceLuncher    bool `json:"service_luncher"`
					ExecutableDropped bool `json:"executable_dropped"`
					Multiprocessing   bool `json:"multiprocessing"`
					CrashedApps       bool `json:"crashed_apps"`
					DebugOutput       bool `json:"debug_output"`
					Stealing          bool `json:"stealing"`
					Exploitable       bool `json:"exploitable"`
					StaticDetections  bool `json:"static_detections"`
					SuspStruct        bool `json:"susp_struct"`
					Autostart         bool `json:"autostart"`
					LowAccess         bool `json:"low_access"`
				} `json:"specs"`
				Type            string `json:"type"`
				Important       bool   `json:"important"`
				ImportantReason string `json:"important_reason"`
				ImportantSince  struct {
					Date int64 `json:"$date"`
				} `json:"important_since"`
				Injected     interface{}   `json:"injected"`
				Serviced     interface{}   `json:"serviced"`
				IsMainObject bool          `json:"isMainObject"`
				IsDropped    bool          `json:"isDropped"`
				IsSigned     bool          `json:"isSigned"`
				IsInjected   bool          `json:"isInjected"`
				IsLoadSusp   bool          `json:"isLoadSusp"`
				WasBefore    bool          `json:"wasBefore"`
				FileType     string        `json:"fileType"`
				Signs        []interface{} `json:"signs"`
			} `json:"scores"`
			Status int `json:"status"`
		} `json:"fields"`
	}

	RawIncident struct {
		Msg        string `json:"msg"`
		Collection string `json:"collection"`
		ID         string `json:"id"`
		Fields     struct {
			Task struct {
				Type  string `json:"$type"`
				Value string `json:"$value"`
			} `json:"task"`
			ProcessOID struct {
				Type  string `json:"$type"`
				Value string `json:"$value"`
			} `json:"processOID"`
			Threatlevel int    `json:"threatlevel"`
			Title       string `json:"title"`
			FirstSeen   struct {
				Date int64 `json:"$date"`
			} `json:"firstSeen"`
			Mitre []string `json:"mitre"`
		} `json:"fields"`
	}
)

func (task *RawTask) GetIdentity() string {
	mainObject := task.Fields.Public.Objects.MainObject
	format := "UUID: %s, MD5: %s, name: %s"
	switch mainObject.Type {
	case "file":
		return fmt.Sprintf(format, task.Fields.UUID, mainObject.Hashes.Md5, mainObject.Names.Basename)
	case "url":
		return fmt.Sprintf(format, task.Fields.UUID, mainObject.Hashes.Md5, mainObject.Names.URL)
	}
	return "[unknown]"
}

func ToJson(i interface{}) string {
	buffer, err := json.MarshalIndent(i, "", " ")
	if err != nil {
		return err.Error()
	}
	return string(buffer)
}

func GetStrMapKeys(m map[string]string) []string {
	keys := make([]string, 0)
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func GetIntMapKeys(m map[string]int) []string {
	keys := make([]string, 0)
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func FormatStrSlice(values []string) string {
	tokens := make([]string, 0)
	for _, v := range values {
		tokens = append(tokens, fmt.Sprintf(`"%s"`, v))
	}
	return fmt.Sprintf(`[%s]`, strings.Join(tokens, ","))
}
