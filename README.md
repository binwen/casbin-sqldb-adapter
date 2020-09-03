Sqldb adapter for Casbin
-----
目前支持以下方法：
----
方法 | 说明 | 
----|------|
LoadPolicy()|从存储中加载所有策略规则 |
SavePolicy()|将所有策略规则保存到存储中 |
AddPolicy()	|向存储中添加策略规则|
BulkAddPolicy()|批量向存储中添加策略规则|
RemovePolicy()|从存储中删除策略规则 |
BulkRemovePolicy|从存储中批量删除策略规则|
RemoveFilteredPolicy()|从存储中删除匹配筛选器的策略规则 |

支持Auto-Save 自动保存机制 
		
	
## 安装

    go get github.com/binwen/casbin-sqldb-adapter

## 存储为mysql的栗子

```go
package main

import (
	"github.com/binwen/sqldb"
	_ "github.com/binwen/sqldb/dialects/mysql"
	"github.com/casbin/casbin/v2"

	sqldbadapter "github.com/binwen/casbin-sqldb-adapter"
)

func main() {
	adapter := sqldbadapter.NewAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/") // Your driver and data source. 
	enforcer, _ := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	
	// 从数据库加载规则
	_ = enforcer.LoadPolicy()
	// 检查权限
	_,_ = enforcer.Enforce("alice", "data1", "read")
	
	// 保存规则至数据库
	enforcer.SavePolicy()
}
```