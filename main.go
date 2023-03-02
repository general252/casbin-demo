package main

import (
	"github.com/general252/casbin-demo/rbac_02"
	"log"
)

// dot hello.gv -Tpng -o image.png

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	// rbac_01.Rbac01()
	rbac_02.Rbac02()
}
