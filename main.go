// contained: A simple Docker service for running files in a container.

// (c) Copyright Nicko van Someren, 2024
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/docker/docker/api/types/container"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/mattn/go-shellwords"
)

type StreamOutput struct {
	Type      string  `json:"type"`
	TimeSince float64 `json:"ts,omitempty"`
	Text      string  `json:"text,omitempty"`
	ExitCode  int     `json:"code,omitempty"`
}

type OutputJSON struct {
	Outputs []StreamOutput `json:"outputs"`
}

// DockerJob represents a job for the Docker executor.

type JobFileItem struct {
	Name string `json:"name" valid:"required"`
	Text string `json:"text" valid:"required"`
}

type DockerJob struct {
	Files []JobFileItem `json:"files" valid:"required"`
	Args  []string      `json:"args"`
}

var tempMountDir string
var tempMountVolume string
var dockerImageName string
var commandPrefix []string
var runAsUser int
var runAsGroup int
var containerCPULimit float64
var maxContainerRunTime int

//  Why doesn't Go have a ternary operator?

func If[T any](cond bool, trueValue, falseValue T) T {
	if cond {
		return trueValue
	}
	return falseValue
}

func findMount(targetPath string) (string, error) {
	fh, err := os.Open("/etc/hostname")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = fh.Close()
	}()

	text, err := io.ReadAll(fh)
	if err != nil {
		return "", err
	}

	containerID := strings.TrimSpace(string(text))

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = cli.Close()
	}()

	containerInfo, err := cli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return "", err
	}

	for _, mountInfo := range containerInfo.Mounts {
		if mountInfo.Destination == targetPath {
			if mountInfo.Type == "bind" {
				return mountInfo.Source, nil
			} else if mountInfo.Type == "volume" {
				volumeInfo, err := cli.VolumeInspect(context.Background(), mountInfo.Name)
				if err != nil {
					return "", err
				}
				dir, _ := filepath.Split(volumeInfo.Mountpoint)
				dir = filepath.Clean(dir)
				_, endDir := filepath.Split(dir)
				return endDir, nil
			} else {
				return "", errors.New("mountInfo must be of type 'bind' or 'volume'")
			}
		}
	}

	return "", errors.New("mountInfo directory not found")
}

// saveTemporaryFiles saves the provided files as temporary files.
// It returns either the path to the temporary files or an error
// When a path is returned it is the callers responsibility to
// clean up the directory.
func saveTemporaryFiles(files []JobFileItem) (string, error) {
	tmpDir, err := os.MkdirTemp(tempMountDir, "tmp")
	if err != nil {
		goto DONE
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	for itemIndex := range files {
		item := files[itemIndex]
		name := filepath.Clean(item.Name)
		if name[:2] == ".." {
			err = errors.New("invalid file path")
		}
		err = os.WriteFile(filepath.Join(tmpDir, name), []byte(item.Text), 0644)
		if err != nil {
			goto DONE
		}
	}

	err = filepath.Walk(tmpDir, func(filePath string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(filePath, runAsUser, runAsGroup)
	})
	if err != nil {
		goto DONE
	}

DONE:
	if err != nil {
		return "", err
	} else {
		return tmpDir, nil
	}
}

func runDocker(outputChannel chan<- StreamOutput, imageName string, files []JobFileItem, timeout int, args []string) error {
	var err error = nil
	rc := -1

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		outputChannel <- StreamOutput{Type: "error", Text: err.Error()}
		return err
	}
	defer func() {
		_ = cli.Close()
	}()

	tmpDir, err := saveTemporaryFiles(files)
	if err != nil {
		outputChannel <- StreamOutput{Type: "error", Text: err.Error()}
		return err
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	tempRelPath, _ := filepath.Rel(tempMountDir, tmpDir)

	containerConfig := &container.Config{
		Image:      imageName,
		Cmd:        args,
		Tty:        false,
		WorkingDir: "/workdir",
		User:       strconv.Itoa(runAsUser) + ":" + strconv.Itoa(runAsGroup),
	}
	hostConfig := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeVolume,
				Source: tempMountVolume,
				Target: "/workdir",
				VolumeOptions: &mount.VolumeOptions{
					NoCopy:  true,
					Subpath: tempRelPath,
				},
			},
		},
	}

	if containerCPULimit != 0.0 {
		hostConfig.Resources = container.Resources{
			NanoCPUs: int64(containerCPULimit * 1_000_000_000),
		}
	}

	resp, err := cli.ContainerCreate(ctx, containerConfig, hostConfig, &network.NetworkingConfig{}, nil, "")
	if err != nil {
		outputChannel <- StreamOutput{Type: "error", Text: err.Error()}
		return err
	}

	defer func() {
		_ = cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
	}()

	startTime := time.Now()

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		outputChannel <- StreamOutput{Type: "error", Text: err.Error()}
		return err
	}

	outReader, err := cli.ContainerLogs(ctx, resp.ID, container.LogsOptions{ShowStdout: true, ShowStderr: true, Follow: true})
	if err != nil {
		outputChannel <- StreamOutput{Type: "error", Text: err.Error()}
		return err
	}
	defer func() {
		_ = outReader.Close()
	}()

	wg := sync.WaitGroup{}
	wg.Add(1)
	var readerErr error

	go func() {
		buf := make([]byte, 8)
		for {
			_, err := io.ReadFull(outReader, buf)
			if err != nil && err != io.EOF {
				readerErr = err
				return
			}

			if err == io.EOF {
				break
			}

			header := binary.BigEndian.Uint64(buf)
			length := header & 0xFFFFFFFF
			isStdErr := (header >> 56) == 2
			now := time.Now()
			elapsed := now.Sub(startTime)

			data := make([]byte, length)
			_, err = io.ReadFull(outReader, data)
			if err != nil {
				readerErr = err
				return
			}

			output := StreamOutput{
				Type:      If(isStdErr, "stderr", "stdout"),
				TimeSince: elapsed.Seconds(),
				Text:      string(data),
			}
			outputChannel <- output
		}

		wg.Done()
	}()

	completionWaiter, errorWaiter := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)

	select {
	case <-time.After(time.Duration(timeout) * time.Second):
		outputChannel <- StreamOutput{Type: "error", Text: "Process timed out"}
		_ = cli.ContainerKill(ctx, resp.ID, "SIGKILL")

	case response := <-completionWaiter:
		rc = int(response.StatusCode)

	case err = <-errorWaiter:
		if err != nil {
			outputChannel <- StreamOutput{Type: "error", Text: err.Error()}
		}
	}

	wg.Wait()

	if readerErr != nil {
		outputChannel <- StreamOutput{Type: "error", Text: err.Error()}
	}

	inspect, err := cli.ContainerInspect(ctx, resp.ID)
	if err != nil {
		outputChannel <- StreamOutput{Type: "error", Text: err.Error()}
	} else {
		rc = inspect.State.ExitCode
	}

	outputChannel <- StreamOutput{Type: "rc", ExitCode: rc}

	return nil
}

func DockerJobHandler(w http.ResponseWriter, r *http.Request, streaming bool) {
	var job DockerJob
	var err error

	if r.Method != "POST" {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	err = json.NewDecoder(r.Body).Decode(&job)
	if err == nil {
		_, err = govalidator.ValidateStruct(job)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Default to the name of the first file if no arguments are given
	args := job.Args
	if len(args) == 0 {
		firstFileName := job.Files[0].Name
		args = append(args, firstFileName)
	}
	args = append(commandPrefix, args...)

	resultChannel := make(chan StreamOutput)

	var serverError error
	go func() {
		serverError = runDocker(resultChannel, dockerImageName, job.Files, maxContainerRunTime, args)
		close(resultChannel)
	}()

	// Create a new JSON encoder that writes to the response writer
	encoder := json.NewEncoder(w)

	if streaming {
		// Set headers for streaming response
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)

		for msg := range resultChannel {
			err := encoder.Encode(msg)
			if err != nil {
				// If there's an error writing to the response, log it and break the loop
				log.Printf("Error encoding message: %v", err)
				break
			}
			// Flush the response writer to send the data immediately
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}

		// Too late to set the header
		if serverError != nil {
			log.Printf("Server error: %v", serverError)
		}
	} else {
		var results []StreamOutput

		for msg := range resultChannel {
			results = append(results, msg)
		}

		if serverError != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}

		err = encoder.Encode(OutputJSON{Outputs: results})
		if err != nil {
			log.Printf("Error encoding message: %v", err)
		}
	}
}

func JSONDockerJobHandler(w http.ResponseWriter, r *http.Request) {
	DockerJobHandler(w, r, false)
}

func StreamingDockerJobHandler(w http.ResponseWriter, r *http.Request) {
	DockerJobHandler(w, r, true)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	var err error
	http.HandleFunc("/", JSONDockerJobHandler)
	http.HandleFunc("/stream", StreamingDockerJobHandler)

	tempMountDir = "/uploads"

	port := getEnv("SERVICE_PORT", "8080")
	dockerImageName = getEnv("DOCKER_IMAGE", "python:alpine")
	commandPrefixString := getEnv("COMMAND_PREFIX", "python")
	runAsUserString := getEnv("CONTAINED_USER", "65534")
	containerCPULimitString := getEnv("CONTAINER_CPU_LIMIT", "0.0")
	maxContainerRunTimeString := getEnv("MAX_CONTAINER_RUN_TIME", "60")

	runUserParts := strings.Split(runAsUserString, ":")

	partCount := len(runUserParts)
	switch partCount {
	case 2:
		runAsGroup, err = strconv.Atoi(runUserParts[1])
		if err != nil || runAsGroup < 0 || runAsGroup > 65534 {
			log.Fatalf("Group ID must be a valid number: %s", runUserParts[1])
		}
		fallthrough
	case 1:
		runAsUser, err = strconv.Atoi(runUserParts[0])
		if err != nil || runAsUser < 0 || runAsUser > 65534 {
			log.Fatalf("User ID must be a valid number: %s", runUserParts[0])
		}
		if partCount == 1 {
			runAsGroup = runAsUser
		}
	default:
		log.Fatalf("Invalid container user: %s", runAsUserString)
	}

	containerCPULimit, err := strconv.ParseFloat(containerCPULimitString, 64)
	if err != nil || containerCPULimit < 0 || containerCPULimit > 64 {
		log.Fatalf("Invalid CPU limit: %s (must be a positive float in range 0<=n<=64)", containerCPULimitString)
	}

	maxContainerRunTime, err = strconv.Atoi(maxContainerRunTimeString)
	if err != nil || maxContainerRunTime < 0 || maxContainerRunTime > 3600 {
		log.Fatalf("Invalid max container run time: %s (must be in in range 0<n<=3600)", maxContainerRunTimeString)
	}

	commandPrefix, err = shellwords.Parse(commandPrefixString)
	if err != nil {
		log.Fatalf("Malformed command prefix: %v", err)
	}

	tempMountVolume, err = findMount(tempMountDir)
	if err != nil {
		log.Fatalf("Failed to find mount: %v", err)
	}

	portNum, err := strconv.Atoi(port) // validate port is an integer.
	if err != nil || portNum < 1 || portNum > 65535 {
		log.Fatalf("Invalid port number: %s (most be int in range 0<n<65536)", port)
	}

	log.Printf("Listening on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
