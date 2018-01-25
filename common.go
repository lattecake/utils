package utils

import (
	"strings"
	"net"
)

// 本机ip地址
func LocalAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		var ip string
		for _, address := range addrs {
			// 检查ip地址判断是否回环地址
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ip += ipnet.IP.To4().String() + ","
				}
			}
		}
		ip = strings.TrimRight(ip, ",")
		return ip
	}
	return "127.0.0.1"
}
