package ewatch

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/antonmedv/expr"
)

type QueryData map[string]interface{}

func (q QueryData) DoMessage(fstring string, a ...any) string {
	return fmt.Sprintf(fstring, a...)
}

func (q QueryData) InAny(a any) bool {
	return lookup(q, a)
}

func (q QueryData) MatchesAny(rx string) bool {
	return rxlookup(q, rx)
}

func (cf *EWatcher) ruleMatches(jsn, qry string) (bool, string) {
	var final string
	if cf.DisableRules || qry == "" {
		if cf.Spawn == nil {
			return true, ""
		} else {
			qry = `( "` + filepath.Base(cf.Spawn.ProcessImage) + `" matches any || ` + strconv.Itoa(int(cf.Spawn.ProcessId)) + ` in any )`
		}
	} else {
		if cf.Spawn != nil {
			qry = qry + ` && ( "` + filepath.Base(cf.Spawn.ProcessImage) + `" matches any || ` + strconv.Itoa(int(cf.Spawn.ProcessId)) + ` in any)`
		}
	}

	if cf.Append != "" {
		// qry = qry + ` && ` + cf.append
		qry = qry + ` ` + cf.Append
	}

	final = qry
	qry = preprocInAny(qry)
	qry = preprocMatchesAny(qry)

	mp := make(QueryData)
	json.Unmarshal([]byte(jsn), &mp)

	if cf.RuleDbg {
		cf.Logger.WriteDebug("[RULE DEBUG]", qry)
	}

	output, err := expr.Eval(qry, mp)
	if err != nil {
		cf.Logger.WriteErr("failed to parse query: ", qry+"\n", err)
		os.Exit(1)
		return false, final
	}
	return fmt.Sprintf("%v", output) == "true", final

}

func lookup(m map[string]interface{}, a any) bool {
	for _, v := range m {
		switch v.(type) {
		case map[string]interface{}:
			if lookup(v.(map[string]interface{}), a) {
				return true
			}
		default:
			// match, _ := regexp.MatchString("p([a-z]+)ch", "peach")
			if fmt.Sprintf("%v", v) == fmt.Sprintf("%v", a) {
				return true
			}
		}
	}
	return false

}

func rxlookup(m map[string]interface{}, rx string) bool {
	for _, v := range m {
		switch v.(type) {
		case map[string]interface{}:
			if lookup(v.(map[string]interface{}), rx) {
				return true
			}
		default:
			match, err := regexp.MatchString(rx, fmt.Sprintf("%v", v))
			if err != nil {
				log.Fatal("failed to parse MatchesAny expression:", rx, "\n", err)
			}
			if match {
				return true
			}
		}
	}
	return false

}

func preprocInAny(query string) string {
	cnt := 0
	for {
		cnt++
		if cnt > 100 { // in case something odd in the rule breaks the replacer
			break
		}
		if strings.Contains(query, " in any") {
			ind := strings.Index(query, " in any")
			quoted := false
			tmp := strings.FieldsFunc(query[0:ind], func(r rune) bool {
				if r == '"' {
					quoted = !quoted
				}
				return !quoted && r == ' '
			})

			parm := tmp[len(tmp)-1]
			replaced := strings.ReplaceAll(query, parm+" in any", "InAny("+parm+")")
			query = replaced
		} else {
			break
		}
	}
	return query
}

func preprocMatchesAny(query string) string {
	cnt := 0
	for {
		cnt++
		if cnt > 100 { // in case something odd in the rule breaks the replacer
			break
		}
		if strings.Contains(query, " matches any") {
			ind := strings.Index(query, " matches any")
			quoted := false
			tmp := strings.FieldsFunc(query[0:ind], func(r rune) bool {
				if r == '"' {
					quoted = !quoted
				}
				return !quoted && r == ' '
			})

			parm := tmp[len(tmp)-1]
			replaced := strings.ReplaceAll(query, parm+" matches any", "MatchesAny("+parm+")")
			query = replaced
		} else {
			break
		}
	}
	return query
}
