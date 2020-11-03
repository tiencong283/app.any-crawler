package main

import (
	"flag"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	configFilePath string
	startTaskIndex uint
	numOfTasks     uint
)

func init() {
	rand.Seed(time.Now().UnixNano())
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	})
	flag.StringVar(&configFilePath, "c", "config.yml", "the `configuration` file")
	flag.StringVar(&configFilePath, "config", "config.yml", "the `configuration` file")
	flag.UintVar(&startTaskIndex, "i", 0, "crawl tasks start from the `index`")
	flag.UintVar(&startTaskIndex, "index", 0, "crawl tasks start from the `index`")
	flag.UintVar(&numOfTasks, "n", 0, "number of tasks to crawl")
	flag.UintVar(&numOfTasks, "number", 0, "number of tasks to crawl")
}

// app.any.run endpoint
var endpointList = [...]string{
	"wss://app.any.run/sockjs/399/i73_d8dy/websocket",
	"wss://app.any.run/sockjs/529/c95zff_m/websocket",
}

func main() {
	flag.Parse()
	appConfig, err := ReadAppConfig(configFilePath)
	if err != nil {
		log.Fatal().Err(err).Msgf("failed to parse configuration file '%s'", configFilePath)
	}

	reqHeader := make(http.Header)
	reqHeader.Add("Host", "app.any.run")
	reqHeader.Add("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0")
	reqHeader.Add("Origin", "https://app.any.run")

	config := &AppAnyClientConfig{
		Endpoint:  endpointList[rand.Intn(len(endpointList))],
		ReqHeader: reqHeader,
		AppConfig: appConfig,
	}
	client, err := NewAppAnyClient(config)
	if err != nil {
		log.Fatal().Err(err).Msg("in NewAppAnyClient")
	}
	if err := client.Connect(); err != nil {
		log.Fatal().Err(err).Msg("unable to send connect msg")
	}
	log.Info().Msg("connected to App.Any.Run")

	totalTaskCount, err := client.GetNumOfTasks()
	if err != nil {
		log.Fatal().Err(err).Msg("in GetNumOfTasks")
	}
	log.Info().Msgf("Number of possible tasks: %d", totalTaskCount)
	if startTaskIndex >= totalTaskCount {
		log.Fatal().Msgf("the requested start index (%d) must not be less than number of tasks available (%d)", startTaskIndex, totalTaskCount)
	}
	if numOfTasks == 0 {
		numOfTasks = totalTaskCount - startTaskIndex
	}
	if startTaskIndex+numOfTasks > totalTaskCount {
		numOfTasks = totalTaskCount - startTaskIndex
		log.Warn().Msgf("only able to crawl %d tasks", numOfTasks)
	}
	log.Info().Msgf("Start crawling tasks (number %d, startIndex: %d)", numOfTasks, startTaskIndex)
	tasks, err := client.GetTasks(int(numOfTasks), int(startTaskIndex))
	if err != nil {
		log.Fatal().Err(err).Msg("in GetProcesses")
	}
	for _, task := range tasks {
		log.Info().Msg(task.GetIdentity())
	}
}
