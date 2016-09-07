package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"time"

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
	msg := `echo "Started %s $(date)"; sleep 10; echo "Stopped %s $(date)"`
	hello := func() {
		out, err := exec.Command("powershell", "-c", fmt.Sprintf(msg, "hello", "hello")).Output()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("ran hello", string(out))
	}
	nc.Subscribe("foo", func(m *nats.Msg) {
		log.Printf("Received a message: %s\n", string(m.Data))
		hello()
	})
	nc.Flush()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	sleeper := make(chan bool, 1)
	go func() {
		for {
			time.Sleep(1 * time.Second)
			sleeper <- true
		}
	}()

	sleepy := func() {
		out, err := exec.Command("powershell", "-c", fmt.Sprintf(msg, "sleepy", "sleepy")).Output()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Slept for 10 seconds", string(out))
	}

	for {
		fmt.Println("Looping...")
		select {
		case s := <-c:
			fmt.Println("Got signal:", s)
			nc.Close()
			return
		case <-sleeper:
			fmt.Println("Staring to sleep")
			sleepy()
		}
	}

}
