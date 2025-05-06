package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const socketPathMain = "/var/run/pyroute2/fdpass"
const socketPathServer = "/var/run/pyroute2/api"
const lockFile = "/var/run/pyroute2/plugin-lock"

type RequestPayload struct {
	CNI map[string]interface{} `json:"cni"`
	Env map[string]string      `json:"env"`
	Rid string                 `json:"rid"`
}

type PluginResponse struct {
	CNIVersion string `json:"cniVersion"`
	IPs        []struct {
		Version string `json:"version"`
		Address string `json:"address"`
	} `json:"ips"`
}

func forwardRequestToServer(input RequestPayload, nameSpaceFD int) ([]byte, error) {
	// 8<------------------------------------------------------------------
	// get request id
	streamSock, err := net.Dial("unix", socketPathServer)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to UNIX socket: %v", err)
	}
	defer streamSock.Close()

	// pack the request
	data := map[string]map[string]string{"cni": {"cniVersion": "0.3.1"}}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode JSON: %v", err)
	}

	// send the request
	_, err = streamSock.Write(jsonData)
	if err != nil {
		return nil, fmt.Errorf("failed to send init request: %v", err)
	}

	// recv the response
	buffer := make([]byte, 4096)
	n, err := streamSock.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to recv init response: %v", err)
	}
	fmt.Fprintf(os.Stderr, "recv init: %s\n", buffer[:n])

	// parse the response
	var response map[string]string
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse init response: %v", err)
	}

	// get request id
	rid, exists := response["rid"]
	if !exists {
		return nil, fmt.Errorf("failed to get rid: %v", err)
	}

	// 8<------------------------------------------------------------------
	// send the fd
	sock, err := net.Dial("unixgram", socketPathMain)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to UNIX socket: %v", err)
	}
	defer sock.Close()

	unixSock, err := sock.(*net.UnixConn).File()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw socket descriptor: %v", err)
	}
	defer unixSock.Close()

	var rights []byte
	if nameSpaceFD > 0 {
		rights = syscall.UnixRights(nameSpaceFD)
	}

	data_fd := map[string]string{"rid": rid}
	jsonData, err = json.Marshal(data_fd)
	err = unix.Sendmsg(int(unixSock.Fd()), jsonData, rights, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}


	// 8<------------------------------------------------------------------

	// add request id and encode payload
	input.Rid = rid
	payloadBytes, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to serialize payload: %v\n", err)
		os.Exit(1)
	}

	// send the request
	_, err = streamSock.Write(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send init request: %v", err)
	}

	// get the response
	n, err = streamSock.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to receive response: %w", err)
	}

	return buffer[:n], nil
}

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read stdin: %v\n", err)
		os.Exit(1)
	}

	flock, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open lock file: %v\n", err)
		os.Exit(1)
	}
	defer flock.Close()

	for {
		err := syscall.Flock(int(flock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	// ensure VRF module
	vrfPath := "/proc/sys/net/vrf"

	if _, err := os.Stat(vrfPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "%s not found. Attempting to load VRF kernel module\n", vrfPath)

		cmd := exec.Command("modprobe", "vrf")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load VRF module: %v\n", err)
			os.Exit(1)
		}
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking VRF path: %v\n", err)
		os.Exit(1)
	}

	var cniData map[string]interface{}
	if err := json.Unmarshal(input, &cniData); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse stdin JSON: %v\n", err)
		os.Exit(1)
	}

	env := make(map[string]string)
	var nameSpace *os.File
	nameSpaceFD := -1
	for _, e := range os.Environ() {
		parts := bytes.SplitN([]byte(e), []byte("="), 2)
		if len(parts) == 2 {
			env[string(parts[0])] = string(parts[1])
			if string(parts[0]) == "CNI_NETNS" {
				nameSpace, err = os.Open(string(parts[1]))
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to open netns: %v\n", err)
				}
				nameSpaceFD = int(nameSpace.Fd())
				defer nameSpace.Close()
			}
		}
	}

	if nameSpaceFD == -1 {
		fmt.Fprintf(os.Stderr, "no CNI_NETNS received\n")
	}

	payload := RequestPayload{
		CNI: cniData,
		Env: env,
	}

	// responseBody, err := sendToHTTPServer(payloadBytes)
	responseBody, err := forwardRequestToServer(payload, nameSpaceFD)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to send to HTTP server: %v\n", err)
		os.Exit(1)
	}

	var response PluginResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode server response: %v\n", err)
		os.Exit(1)
	}

	output, err := json.Marshal(response)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode response: %v\n", err)
		os.Exit(1)
	}
	syscall.Flock(int(flock.Fd()), syscall.LOCK_UN)
	fmt.Println(string(output))
}
