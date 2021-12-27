package main

const whitelistTTL = 1 // 24 hours

var (
	c Configuration
	r RedisConfiguration
	h Authentication
	w Whitelist
	a Azure
)

func main() {
	w.init()
}
