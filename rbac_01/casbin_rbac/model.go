package casbin_rbac

type CasbinRule struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Ptype string `gorm:"size:100;uniqueIndex:unique_index"`
	V0    string `gorm:"size:100;uniqueIndex:unique_index"`
	V1    string `gorm:"size:100;uniqueIndex:unique_index"`
	V2    string `gorm:"size:100;uniqueIndex:unique_index"`
	V3    string `gorm:"size:100;uniqueIndex:unique_index"`
	V4    string `gorm:"size:100;uniqueIndex:unique_index"`
	V5    string `gorm:"size:100;uniqueIndex:unique_index"`
}

func (tis *CasbinRule) TableName() string {
	return "casbin_rule_a"
}

type ActionType string

func (c ActionType) String() string {
	return string(c)
}

const (
	ActionTypePost ActionType = "post" // 增加
	ActionTypeGet  ActionType = "get"  // 获取
	ActionTypePut  ActionType = "put"  // 修改
	ActionTypeDel  ActionType = "del"  // 删除
)
