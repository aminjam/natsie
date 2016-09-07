package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/nats-io/nats"
)

var natsIp string

func init() {
	flag.StringVar(&natsIp, "nats", "", "nats IP")
}

func main() {
	flag.Parse()
	fmt.Println(natsIp)
	nc, err := nats.Connect(fmt.Sprintf("nats://%s:4222", natsIp))
	if err != nil {
		log.Fatal(err)
	}
	nc.Subscribe("foo", func(m *nats.Msg) {
		fmt.Printf("Received a message: %s\n", string(m.Data))
	})
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// Block until a signal is received.
	s := <-c
	fmt.Println("Got signal:", s)
	nc.Close()
}
