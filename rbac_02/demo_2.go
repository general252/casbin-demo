package rbac_02

import (
	"fmt"
	"github.com/general252/casbin-demo/rbac_02/rbac_org"
	"log"
	"os"
	"strings"
)

const (
	dataSource = "root:123456@tcp(127.0.0.1:3306)/casbin"

	modelString = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub) && g2(r.obj, p.obj) && r.act == p.act || r.sub == "root"
`
)

func Rbac02() {
	e := rbac_org.NewRbacOrg()
	e.Init(modelString)

	e.AddUser("tina", "ug_HeFei")
	e.AddUser("tony", "ug_HeFei")
	e.AddUser("alice", "ug_AnHui")
	e.AddUser("bob", "ug_ZhengZhou")
	e.AddUser("john", "ug_China")

	e.AddDevice("PU_LuoShanJi", "pg_USA")
	e.AddDevice("PU_HuaShengDun", "pg_USA")
	e.AddDevice("PU_LaSiWeiJiaSi", "pg_USA")
	e.AddDevice("PU_BaLi", "pg_FaGuo")
	e.AddDevice("PU_BoLin", "pg_OuMeng")

	e.AddOrg("ug_HeFei", "ug_AnHui")
	e.AddOrg("ug_AnHui", "ug_China")
	e.AddDeviceGroup("pg_FaGuo", "pg_OuMeng")

	e.AddPermission(e.GetWrapOrg("ug_HeFei"), e.GetWrapResourceGroup("pg_OuMeng"))
	e.AddPermission(e.GetWrapOrg("ug_ZhengZhou"), e.GetWrapResource("PU_BaLi"))

	e.AddPermission(e.GetWrapOrg("ug_ZhengZhou"), e.GetWrapResourceGroup("pg_USA"))
	//e.AddPermission(e.GetWrapUser("john"), e.GetWrapResource("PU_LuoShanJi"))

	//
	e.Test(e.GetWrapUser("tony"), e.GetWrapResource("PU_HuaShengDun"))
	e.Test(e.GetWrapUser("alice"), e.GetWrapResource("PU_HuaShengDun"))
	e.Test(e.GetWrapUser("tony"), e.GetWrapOrg("ug_HeFei"))
	e.Test(e.GetWrapUser("tony"), e.GetWrapOrg("ug_AnHui"))
	e.Test(e.GetWrapUser("alice"), e.GetWrapOrg("ug_HeFei"))
	e.Test(e.GetWrapUser("alice"), e.GetWrapOrg("ug_AnHui"))

	log.Println("--------------------")

	e.Save()

	v, _ := e.GetDots()
	log.Println(v)

	graphvizImage(v, "hello2.gv")

	if false {
		e.RemoveOrg("ug_HeFei", "ug_AnHui")

		e.Test(e.GetWrapUser("tony"), e.GetWrapResource("PU_HuaShengDun"))
		e.Test(e.GetWrapUser("alice"), e.GetWrapResource("PU_HuaShengDun"))
		e.Test(e.GetWrapUser("tony"), e.GetWrapOrg("ug_HeFei"))
		e.Test(e.GetWrapUser("tony"), e.GetWrapOrg("ug_AnHui"))
		e.Test(e.GetWrapUser("alice"), e.GetWrapOrg("ug_HeFei"))
		e.Test(e.GetWrapUser("alice"), e.GetWrapOrg("ug_AnHui"))
	}
}

func graphvizImage(dots []rbac_org.CasbinRule, outfile string) {

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

	_ = os.WriteFile(outfile, []byte(gv), os.ModePerm)
}
