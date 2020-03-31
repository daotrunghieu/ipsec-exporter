package ipsec

import (
	"os/exec"
	"regexp"
	"strconv"
	"github.com/prometheus/common/log"
)

type status struct {
	up         bool
	status     connectionStatus
	bytesIn    int
	bytesOut   int
	packetsIn  int
	packetsOut int
}

type connectionStatus int

const (
	tunnelInstalled       connectionStatus = 0
	connectionEstablished connectionStatus = 1
	down                  connectionStatus = 2
	unknown               connectionStatus = 3
	ignored               connectionStatus = 4
)

func queryStatus(ipSecConfiguration *Configuration) map[string]*status {
	statusMap := map[string]*status{}

	for _, connection := range ipSecConfiguration.tunnel {
		if connection.ignored {
			statusMap[connection.name] = &status{
				up:     true,
				status: ignored,
			}
			continue
		}

		out1, err1 := exec.Command("ipsec", "status").Output()
		out2, err2 := exec.Command("ipsec", "whack", "--trafficstatus").Output()

		if err1 != nil || err2 !=nil {
			log.Warnf("Unable to retrieve the status of tunnel '%s'. Reason: %v", connection.name, err1)
			log.Warnf("Unable to retrieve the status of tunnel '%s'. Reason: %v", connection.name, err2)
			statusMap[connection.name] = &status{
				up:     false,
				status: unknown,
			}
		} else {
			stutas := status{up:true}

			tunnelEstablishedRegex := regexp.MustCompile(connection.name + `.*erouted`)
			connectionEstablishedRegex := regexp.MustCompile(connection.name + `.*established`)

			if connectionEstablishedRegex.Match(out1) {
				if tunnelEstablishedRegex.Match(out1) {
					stutas.status = tunnelInstalled
				} else {
					stutas.status = connectionEstablished
				}
			} else {
				stutas.status = down
			}

			stutas.bytesIn    = extractIntWithRegex(string(out2), connection.name + `.*inBytes=([0-9]+)`)
			stutas.bytesOut   = extractIntWithRegex(string(out2), connection.name + `.*outBytes=([0-9]+)`)
			stutas.packetsIn  = extractIntWithRegex(string(out2), connection.name + `bytes_i \(([[0-9]+) pkts`)
			stutas.packetsOut = extractIntWithRegex(string(out2), connection.name + `bytes_o \(([[0-9]+) pkts`)

			statusMap[connection.name] = &stutas
		}
	}

	return statusMap
}

func extractIntWithRegex(input string, regex string) int {
	re := regexp.MustCompile(regex)
	match := re.FindStringSubmatch(input)
	if len(match) >= 2 {
		i, err := strconv.Atoi(match[1])
		if err != nil {
			return 0
		}
		return i
	}

	return 0
}
