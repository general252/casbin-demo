package rbac_org

import (
	"bufio"
	"bytes"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileAdapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"log"
	"os"
	"strings"
)

// RbacOrg 用户组替换为组织机构,
// 上级机构继承其所有下属机构
// (上级机构拥有下属机构的所有权限, 有别于RBAC3中小组织继承上传组织的权限)
type RbacOrg struct {
	e *casbin.Enforcer
}

func NewRbacOrg() *RbacOrg {
	r := &RbacOrg{}
	return r
}

func (tis *RbacOrg) Init(modelString string) error {
	m, err := model.NewModelFromString(modelString)
	if err != nil {
		return err
	}

	if _, err := os.Stat("basic_policy4.csv"); err != nil {
		if fp, err := os.Create("basic_policy4.csv"); err == nil {
			_ = fp.Close()
		}
	}

	a := fileAdapter.NewAdapter("basic_policy4.csv")

	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		return err
	}

	tis.e = e

	return nil
}

// AddUser 添加用户
func (tis *RbacOrg) AddUser(userId string, orgId string) {
	e := tis.e

	userId = tis.GetWrapUser(userId)
	orgId = tis.GetWrapOrg(orgId)

	if _, err := e.AddGroupingPolicy(userId, orgId); err != nil {
		log.Println(err)
	}

	tis.AddPermission(userId, orgId)
}

// RemoveUser 移除用户
func (tis *RbacOrg) RemoveUser(userId string, orgId string) {
	e := tis.e

	userId = tis.GetWrapUser(userId)
	orgId = tis.GetWrapOrg(orgId)

	_, _ = e.RemoveGroupingPolicy(userId, orgId)
	tis.RemovePermission(userId, orgId)
}

// AddOrg 添加组织
func (tis *RbacOrg) AddOrg(orgId string, parentOrgId string) {
	e := tis.e

	orgId = tis.GetWrapOrg(orgId)
	parentOrgId = tis.GetWrapOrg(parentOrgId)

	if _, err := e.AddGroupingPolicy(parentOrgId, orgId); err != nil {
		log.Println(err)
	}

	tis.AddPermission(parentOrgId, orgId)
}

// RemoveOrg 移除组织
func (tis *RbacOrg) RemoveOrg(orgId string, parentOrgId string) {
	e := tis.e

	orgId = tis.GetWrapOrg(orgId)
	parentOrgId = tis.GetWrapOrg(parentOrgId)

	if _, err := e.RemoveGroupingPolicy(parentOrgId, orgId); err != nil {
		log.Println(err)
	}

	tis.RemovePermission(parentOrgId, orgId)
}

// AddDevice 添加设备
func (tis *RbacOrg) AddDevice(deviceId string, groupId string) {
	e := tis.e

	deviceId = tis.GetWrapResource(deviceId)
	groupId = tis.GetWrapResourceGroup(groupId)

	if _, err := e.AddNamedGroupingPolicy("g2", deviceId, groupId); err != nil {
		log.Println(err)
	}
}

// RemoveDevice 移除设备
func (tis *RbacOrg) RemoveDevice(deviceId string, groupId string) {
	e := tis.e

	deviceId = tis.GetWrapResource(deviceId)
	groupId = tis.GetWrapResourceGroup(groupId)

	if _, err := e.RemoveNamedGroupingPolicy("g2", deviceId, groupId); err != nil {
		log.Println(err)
	}
}

// AddDeviceGroup 添加设备组
func (tis *RbacOrg) AddDeviceGroup(groupId string, parentGroupId string) {
	e := tis.e

	groupId = tis.GetWrapResourceGroup(groupId)
	parentGroupId = tis.GetWrapResourceGroup(parentGroupId)

	if _, err := e.AddNamedGroupingPolicy("g2", groupId, parentGroupId); err != nil {
		log.Println(err)
	}
}

// RemoveDeviceGroup 移除设备组
func (tis *RbacOrg) RemoveDeviceGroup(groupId string, parentGroupId string) {
	e := tis.e

	groupId = tis.GetWrapResourceGroup(groupId)
	parentGroupId = tis.GetWrapResourceGroup(parentGroupId)

	if _, err := e.RemoveNamedGroupingPolicy("g2", groupId, parentGroupId); err != nil {
		log.Println(err)
	}
}

// AddPermission 添加权限
//
//	owner: user/org
//	res: device/deviceGroup/org
func (tis *RbacOrg) AddPermission(owner string, res string) {
	e := tis.e
	if _, err := e.AddPolicy(owner, res, "write", "allow"); err != nil {
		log.Println(err)
	}
}

// RemovePermission 移除权限
func (tis *RbacOrg) RemovePermission(owner string, res string) {
	e := tis.e

	_, _ = e.RemovePolicy(owner, res, "write", "allow")
}

// HasPermission 判断权限
//
// owner: user/org
// res: device/deviceGroup/org
func (tis *RbacOrg) HasPermission(owner string, res string) bool {
	e := tis.e

	ok, err := e.Enforce(owner, res, "write")
	if err != nil {
		return false
	}

	return ok
}

func (tis *RbacOrg) Save() {
	e := tis.e

	_ = e.SavePolicy()
}

func (tis *RbacOrg) Test(userId string, res string) {
	log.Printf("%10v -> %-20v %-10v", userId, res, tis.HasPermission(userId, res))
}

func (tis *RbacOrg) GetWrapUser(id string) string {
	return "u_" + id
}

func (tis *RbacOrg) GetWrapOrg(id string) string {
	return "ug_" + id
}

func (tis *RbacOrg) GetWrapResource(id string) string {
	return "r_" + id
}

func (tis *RbacOrg) GetWrapResourceGroup(id string) string {
	return "rg_" + id
}

func (tis *RbacOrg) GetDots() ([]CasbinRule, error) {
	data, err := os.ReadFile("basic_policy4.csv")
	if err != nil {
		return nil, err
	}

	r := bufio.NewReader(bytes.NewReader(data))

	var objects []CasbinRule
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			break
		}
		data := strings.Split(string(line), ",")

		obj := CasbinRule{
			Ptype: "",
			V0:    "",
			V1:    "",
			V2:    "",
			V3:    "",
			V4:    "",
			V5:    "",
		}

		dataLen := len(data)
		if dataLen < 3 {
			continue
		}

		if dataLen >= 1 {
			obj.Ptype = data[0]
		}
		if dataLen >= 2 {
			obj.V0 = data[1]
		}
		if dataLen >= 3 {
			obj.V1 = data[2]
		}
		if dataLen >= 4 {
			obj.V2 = data[3]
		}
		if dataLen >= 5 {
			obj.V3 = data[4]
		}
		if dataLen >= 6 {
			obj.V4 = data[5]
		}
		if dataLen >= 7 {
			obj.V5 = data[6]
		}

		objects = append(objects, obj)
	}

	return objects, nil
}
