package casbin_rbac

import (
	"log"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/gorm-adapter/v3"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type CasbinServer struct {
	db *gorm.DB

	e1 *casbin.Enforcer
}

func NewCasbinServer() *CasbinServer {
	return &CasbinServer{}
}

func (tis *CasbinServer) Init(dataSource string) error {

	db, err := gorm.Open(mysql.Open(dataSource), &gorm.Config{})
	//db, err := gorm.Open(sqlite.Open(filename), &gorm.Config{})
	if err != nil {
		log.Println(err)
		return err
	}
	db.Logger.LogMode(logger.Info)

	tis.db = db
	return nil
}

func (tis *CasbinServer) New(modelString string) error {
	db := tis.db
	objectModel := new(CasbinRule)

	a, err := gormadapter.NewAdapterByDBWithCustomTable(db, objectModel, objectModel.TableName())
	//a, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		log.Println(err)
		return err
	}

	m, err := model.NewModelFromString(modelString)
	if err != nil {
		log.Println(err)
		return err
	}

	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		log.Println(err)
		return err
	}

	e.EnableAutoSave(true)

	tis.e1 = e

	return nil
}

// AddPolicyGroup2Group 用户组对资源组的操作权限 p, user_group, pu_group, read, allow/deny
func (tis *CasbinServer) AddPolicyGroup2Group(userGroup, resourceGroup string, act ActionType, isAllow bool) (bool, error) {
	e := tis.e1

	allow := "allow"
	if !isAllow {
		allow = "deny"
	}

	userGroup = tis.wrapUserGroup(userGroup)
	resourceGroup = tis.wrapResourceGroup(resourceGroup)

	return e.AddPolicy(userGroup, resourceGroup, act.String(), allow)
}

// AddPolicyUser2Group 用户对资源组的操作权限 p, tina, pu_group, read, allow
func (tis *CasbinServer) AddPolicyUser2Group(user, resourceGroup string, act ActionType, isAllow bool) (bool, error) {
	e := tis.e1

	allow := "allow"
	if !isAllow {
		allow = "deny"
	}

	user = tis.wrapUser(user)
	resourceGroup = tis.wrapResourceGroup(resourceGroup)

	return e.AddPolicy(user, resourceGroup, act.String(), allow)
}

// AddPolicyGroup2Resource 用户组对资源的操作权限 p, user_group, pu_2, read, allow/deny
func (tis *CasbinServer) AddPolicyGroup2Resource(userGroup, resource string, act ActionType, isAllow bool) (bool, error) {
	e := tis.e1

	allow := "allow"
	if !isAllow {
		allow = "deny"
	}

	userGroup = tis.wrapUserGroup(userGroup)
	resource = tis.wrapResource(resource)

	return e.AddPolicy(userGroup, resource, act.String(), allow)
}

// AddPolicyUser2Resource 用户对资源的操作权限 p, tina, pu_2, read, allow
func (tis *CasbinServer) AddPolicyUser2Resource(user, resource string, act ActionType, isAllow bool) (bool, error) {
	e := tis.e1

	allow := "allow"
	if !isAllow {
		allow = "deny"
	}

	user = tis.wrapUser(user)
	resource = tis.wrapResource(resource)

	return e.AddPolicy(user, resource, act.String(), allow)
}

// AddUserGroupUser2Group 用户所属用户组 g, user_1, user_group
func (tis *CasbinServer) AddUserGroupUser2Group(user, userGroup string) (bool, error) {
	e := tis.e1

	user = tis.wrapUser(user)
	userGroup = tis.wrapUserGroup(userGroup)

	return e.AddGroupingPolicy(user, userGroup)
}

// AddUserGroupGroup2Group 用户组所属用户组 g, user_group_child, user_group_parent
func (tis *CasbinServer) AddUserGroupGroup2Group(userGroupChild, userGroupParent string) (bool, error) {
	e := tis.e1

	userGroupChild = tis.wrapUserGroup(userGroupChild)
	userGroupParent = tis.wrapUserGroup(userGroupParent)

	return e.AddNamedGroupingPolicy("g", userGroupChild, userGroupParent)
}

// AddResourceGroupResource2Group 资源所属资源组 g2, pu_1, pu_group
func (tis *CasbinServer) AddResourceGroupResource2Group(resource, resourceGroup string) (bool, error) {
	e := tis.e1

	resource = tis.wrapResource(resource)
	resourceGroup = tis.wrapResourceGroup(resourceGroup)

	return e.AddNamedGroupingPolicy("g2", resource, resourceGroup)
}

// AddResourceGroupGroup2Group 资源组所属资源组 g2, resource_group_child, resource_group_parent
func (tis *CasbinServer) AddResourceGroupGroup2Group(resourceGroupChild, resourceGroupParent string) (bool, error) {
	e := tis.e1

	resourceGroupChild = tis.wrapResourceGroup(resourceGroupChild)
	resourceGroupParent = tis.wrapResourceGroup(resourceGroupParent)

	return e.AddNamedGroupingPolicy("g2", resourceGroupChild, resourceGroupParent)
}

// UserHasResource 用户访问资源
func (tis *CasbinServer) UserHasResource(user, resource string, act ActionType) (bool, error) {
	e := tis.e1

	user = tis.wrapUser(user)
	resource = tis.wrapResource(resource)

	return e.Enforce(user, resource, act.String())
}

// UserHasResourceGroup 用户访问资源组
func (tis *CasbinServer) UserHasResourceGroup(user, resourceGroup string, act ActionType) (bool, error) {
	e := tis.e1

	user = tis.wrapUser(user)
	resourceGroup = tis.wrapResourceGroup(resourceGroup)

	return e.Enforce(user, resourceGroup, act.String())
}

// UserGroupHasResourceGroup 用户组访问资源组
func (tis *CasbinServer) UserGroupHasResourceGroup(userGroup, resourceGroup string, act ActionType) (bool, error) {
	e := tis.e1

	userGroup = tis.wrapUserGroup(userGroup)
	resourceGroup = tis.wrapResourceGroup(resourceGroup)

	return e.Enforce(userGroup, resourceGroup, act.String())
}

// UserGroupHasResource 用户组访问资源
func (tis *CasbinServer) UserGroupHasResource(userGroup, resource string, act ActionType) (bool, error) {
	e := tis.e1

	userGroup = tis.wrapUserGroup(userGroup)
	resource = tis.wrapResource(resource)

	return e.Enforce(userGroup, resource, act.String())
}

func (tis *CasbinServer) Test() {
	e := tis.e1

	log.Println(e.GetAllRoles())
}

func (tis *CasbinServer) wrapUser(id string) string {
	return "u_" + id
}

func (tis *CasbinServer) wrapUserGroup(id string) string {
	return "ug_" + id
}

func (tis *CasbinServer) wrapResource(id string) string {
	return "r_" + id
}

func (tis *CasbinServer) wrapResourceGroup(id string) string {
	return "rg_" + id
}

func (tis *CasbinServer) GetDots(dataSource string) ([]CasbinRule, error) {
	dialector := mysql.Open(dataSource)
	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, err
	}

	var objects []CasbinRule
	if err := db.Model(new(CasbinRule)).Find(&objects).Error; err != nil {
		log.Println(err)
		return nil, err
	}

	return objects, nil
}
