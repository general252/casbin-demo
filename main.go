package main

// dot hello.gv -Tpng -o image.png

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/general252/casbin-demo/casbin_rbac"
)

const (
	dataSource = "root:123456@tcp(127.0.0.1:3306)/casbin"
	tableName  = "casbin_rule_a"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	s := casbin_rbac.NewCasbinServer()
	_ = s.Init(dataSource)

	_ = s.New(casbin_rbac.ModelString, tableName)

	// 用户组 -> 用户组
	log.Println(s.AddUserGroupGroup2Group("g1", "g2"))
	log.Println(s.AddUserGroupGroup2Group("g2", "g3"))
	log.Println(s.AddUserGroupGroup2Group("g3", "g4"))
	log.Println(s.AddUserGroupGroup2Group("g3", "g5"))
	log.Println(s.AddUserGroupGroup2Group("g6", "g3"))
	log.Println(s.AddUserGroupGroup2Group("g7", "g3"))
	log.Println(s.AddUserGroupGroup2Group("g8", "g4"))
	log.Println(s.AddUserGroupGroup2Group("g9", "g4"))

	// 用户 -> 用户组
	log.Println(s.AddUserGroupUser2Group("tony", "g2"))
	log.Println(s.AddUserGroupUser2Group("lili", "g2"))
	log.Println(s.AddUserGroupUser2Group("dav", "g4"))
	log.Println(s.AddUserGroupUser2Group("did", "g6"))

	// 资源组 -> 资源组
	log.Println(s.AddResourceGroupGroup2Group("rg1", "rg2"))
	log.Println(s.AddResourceGroupGroup2Group("rg2", "rg3"))
	log.Println(s.AddResourceGroupGroup2Group("rg2", "rg4"))
	log.Println(s.AddResourceGroupGroup2Group("rg4", "rg5"))
	log.Println(s.AddResourceGroupGroup2Group("rg3", "rg5"))
	log.Println(s.AddResourceGroupGroup2Group("rg6", "rg5"))

	// 资源 -> 资源组
	log.Println(s.AddResourceGroupResource2Group("pu_2", "rg2"))
	log.Println(s.AddResourceGroupResource2Group("pu_3", "rg3"))
	log.Println(s.AddResourceGroupResource2Group("pu_4", "rg3"))
	log.Println(s.AddResourceGroupResource2Group("pu_5", "rg4"))
	log.Println(s.AddResourceGroupResource2Group("pu_6", "rg4"))
	log.Println(s.AddResourceGroupResource2Group("pu_7", "rg6"))

	// 用户组 拥有权限 资源组
	log.Println(s.AddPolicyGroup2Group("g2", "rg2", casbin_rbac.ActionTypeGet, true))
	log.Println(s.AddPolicyGroup2Group("g3", "rg3", casbin_rbac.ActionTypePut, true))
	log.Println(s.AddPolicyGroup2Group("g3", "rg3", casbin_rbac.ActionTypePut, true))

	// 用户组 拥有权限 资源
	log.Println(s.AddPolicyGroup2Resource("g3", "pu_6", casbin_rbac.ActionTypePut, true))

	// 用户 拥有权限 资源组
	log.Println(s.AddPolicyUser2Group("did", "rg6", casbin_rbac.ActionTypePut, true))

	// 用户 拥有权限 资源
	log.Println(s.AddPolicyUser2Resource("tina", "pu_1", casbin_rbac.ActionTypeGet, true))

	log.Println(s.UserHasResource("tina", "pu_1", casbin_rbac.ActionTypeGet))
	log.Println(s.UserHasResource("tony", "pu_2", casbin_rbac.ActionTypeGet))

	log.Println(s.UserHasResourceGroup("tony", "rg3", casbin_rbac.ActionTypePut))
	log.Println(s.UserHasResource("tony", "pu_4", casbin_rbac.ActionTypePut))
	log.Println(s.UserHasResource("dav", "pu_4", casbin_rbac.ActionTypePut))
	log.Println(s.UserGroupHasResource("g6", "pu_4", casbin_rbac.ActionTypePut))
	log.Println(s.UserHasResource("did", "pu_7", casbin_rbac.ActionTypePut))

	s.Test()

	graphvizImage(s)
}

func graphvizImage(s *casbin_rbac.CasbinServer) {
	dots, err := s.GetDots(dataSource, tableName)
	if err != nil {
		return
	}

	var getString = func(v string) string {
		if strings.HasPrefix(v, "u_") {
			return fmt.Sprintf("%v[shape=ellipse, style=filled, color=cadetblue4 ];\n", v)
		} else if strings.HasPrefix(v, "r_") {
			return fmt.Sprintf("%v[shape=egg, style=filled, color=chocolate2 ];\n", v)
		} else if strings.HasPrefix(v, "rg_") {
			return fmt.Sprintf("%v[shape=component, style=filled, color=lightgoldenrod1 ];\n", v)
		} else if strings.HasPrefix(v, "ug_") {
			return fmt.Sprintf("%v[shape=folder, style=filled, color=skyblue ];\n", v)
		}

		return ""
	}

	var gv = "digraph G {\n\n"

	for _, dot := range dots {
		gv += getString(dot.V0)
		gv += getString(dot.V1)
	}

	gv += `

subgraph cluster_0 {
	style=filled;
	color=lightgrey;
	fillcolor="darkturquoise:cornsilk2";
	gradientangle=50
`

	for _, dot := range dots {
		if dot.Ptype == "g" {
			gv += fmt.Sprintf("%v->%v[penwidth=2, color=dodgerblue];\n", dot.V0, dot.V1)
		}
	}

	gv += `
}

subgraph cluster_1 {
	style=filled;
	color=lightgrey;
	fillcolor="cornsilk:cadetblue3";
	gradientangle=100

`

	for _, dot := range dots {
		if dot.Ptype == "g2" {
			gv += fmt.Sprintf("%v->%v[penwidth=2, color=red];\n", dot.V1, dot.V0)
		}
	}
	gv += `
}
`

	for _, dot := range dots {
		if dot.Ptype == "p" {
			gv += fmt.Sprintf(
				"%v->%v[penwidth=3, label=\" %v %v \", color=grey28]\n",
				dot.V0, dot.V1, dot.V2, dot.V3)
		}
	}
	gv += "\n\n"

	gv += "}"

	_ = os.WriteFile("hello.gv", []byte(gv), os.ModePerm)
}
