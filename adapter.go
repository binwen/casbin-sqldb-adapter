package sqldbadapter

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/binwen/sqldb"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

const defaultTableName = "casbin_rule"

type CasbinRule struct {
	ID    uint   `db:"id"`
	PType string `db:"p_type"`
	V0    string `db:"v0"`
	V1    string `db:"v1"`
	V2    string `db:"v2"`
	V3    string `db:"v3"`
	V4    string `db:"v4"`
	V5    string `db:"v5"`
}

type Adapter struct {
	tableName  string
	isFiltered bool // 仅加载与过滤器匹配的策略规则
	engine     *sqldb.EngineGroup
}

type AdapterOptions struct {
	Driver       string
	DNS          string
	MaxConns     int
	MaxIdleConns int
	MaxLifetime  int
	ShowSQL      bool
	DBEngine     *sqldb.EngineGroup

	TableName string
}

// 过滤策略
type Filter struct {
	PType []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
}

func finalizer(a *Adapter) {
	if a.engine == nil {
		return
	}

	a.engine.Close()
}

func NewAdapter(driver string, dns string, showSQL ...bool) *Adapter {
	showSql := false
	if len(showSQL) >= 1 {
		showSql = showSQL[0]
	}
	engine, err := sqldb.OpenSingleDBEngine(&sqldb.Config{Driver: driver, DNS: dns}, showSql)
	if err != nil {
		panic(err)
	}
	a := &Adapter{
		tableName: defaultTableName,
		engine:    engine,
	}
	runtime.SetFinalizer(a, finalizer)

	return a
}

func NewAdapterWithDBEngine(engine *sqldb.EngineGroup) *Adapter {
	a := &Adapter{engine: engine, tableName: defaultTableName}
	a.ensureTable()
	return a
}

func NewAdapterWithOptions(opts *AdapterOptions) *Adapter {
	a := &Adapter{tableName: defaultTableName}
	if opts.TableName != "" {
		a.tableName = opts.TableName
	}

	if opts.DBEngine != nil {
		a.engine = opts.DBEngine
	} else {
		engine, err := sqldb.OpenSingleDBEngine(&sqldb.Config{
			Driver:       opts.Driver,
			DNS:          opts.DNS,
			MaxConns:     opts.MaxConns,
			MaxIdleConns: opts.MaxIdleConns,
			MaxLifetime:  opts.MaxLifetime,
		}, opts.ShowSQL)
		if err != nil {
			panic(err)
		}
		a.engine = engine
		runtime.SetFinalizer(a, finalizer)
	}

	a.ensureTable()

	return a
}

// 从存储中加载所有策略规则
func (a *Adapter) LoadPolicy(model model.Model) error {
	rules := make([]*CasbinRule, 0, 64)
	if err := a.engine.Table(a.tableName).Find(&rules); err != nil {
		return err
	}

	for _, rule := range rules {
		loadPolicyRuleLine(rule, model)
	}

	return nil
}

// 将所有策略规则保存到存储中
func (a *Adapter) SavePolicy(model model.Model) (err error) {
	a.cleanTable()
	ruleLines := make([]*CasbinRule, 0, 64)
	for pType, ast := range model["p"] {
		for _, rules := range ast.Policy {
			ruleLine := genPolicyRuleLine(pType, rules)
			ruleLines = append(ruleLines, ruleLine)
		}
	}

	for pType, ast := range model["g"] {
		for _, rules := range ast.Policy {
			ruleLine := genPolicyRuleLine(pType, rules)
			ruleLines = append(ruleLines, ruleLine)
		}
	}

	_, err = a.engine.Table(a.tableName).BulkCreate(ruleLines)
	return
}

// 向存储中添加策略规则
func (a *Adapter) AddPolicy(sec string, pType string, rules []string) (err error) {
	ruleLine := genPolicyRuleLine(pType, rules)
	_, err = a.engine.Table(a.tableName).Create(ruleLine)
	return
}

// 批量向存储中添加策略规则
func (a *Adapter) BulkAddPolicy(sec string, pType string, rules [][]string) (err error) {
	ruleLines := make([]*CasbinRule, 0, 64)
	for _, rule := range rules {
		ruleLine := genPolicyRuleLine(pType, rule)
		ruleLines = append(ruleLines, ruleLine)
	}

	_, err = a.engine.Table(a.tableName).BulkCreate(ruleLines)
	return
}

//从存储中删除策略规则
func (a *Adapter) RemovePolicy(sec, pType string, rules []string) (err error) {
	ruleLine := genPolicyRuleLine(pType, rules)
	_, err = a.engine.Table(a.tableName).Where(map[string]interface{}{
		"p_type": ruleLine.PType,
		"v0":     ruleLine.V0,
		"v1":     ruleLine.V1,
		"v2":     ruleLine.V2,
		"v3":     ruleLine.V3,
		"v4":     ruleLine.V4,
		"v5":     ruleLine.V5,
	}).Delete()
	return
}

// 从存储中批量删除策略规则
func (a *Adapter) BulkRemovePolicy(sec, pType string, rules [][]string) (err error) {
	err = a.engine.Tx(func(db *sqldb.SqlDB) error {
		for _, rule := range rules {
			ruleLine := genPolicyRuleLine(pType, rule)
			if _, err := db.Table(a.tableName).Where(map[string]interface{}{
				"p_type": ruleLine.PType,
				"v0":     ruleLine.V0,
				"v1":     ruleLine.V1,
				"v2":     ruleLine.V2,
				"v3":     ruleLine.V3,
				"v4":     ruleLine.V4,
				"v5":     ruleLine.V5,
			}).Delete(); err != nil {
				return err
			}
		}
		return nil
	})

	return
}

// 从存储中删除匹配筛选器的策略规则
func (a *Adapter) RemoveFilteredPolicy(sec string, pType string, fieldIndex int, fieldValues ...string) (err error) {
	session := a.engine.Table(a.tableName).Where("p_type = ?", pType)
	idx := fieldIndex + len(fieldValues)
	if fieldIndex <= 0 && idx > 0 && fieldValues[0-fieldIndex] != "" {
		session = session.Where("v0 = ?", fieldValues[0-fieldIndex])
	}
	if fieldIndex <= 1 && idx > 1 && fieldValues[1-fieldIndex] != "" {
		session = session.Where("v1 = ?", fieldValues[1-fieldIndex])
	}
	if fieldIndex <= 2 && idx > 2 && fieldValues[2-fieldIndex] != "" {
		session = session.Where("v2 = ?", fieldValues[2-fieldIndex])
	}
	if fieldIndex <= 3 && idx > 3 && fieldValues[3-fieldIndex] != "" {
		session = session.Where("v3 = ?", fieldValues[3-fieldIndex])
	}
	if fieldIndex <= 4 && idx > 4 && fieldValues[4-fieldIndex] != "" {
		session = session.Where("v4 = ?", fieldValues[4-fieldIndex])
	}
	if fieldIndex <= 5 && idx > 5 && fieldValues[5-fieldIndex] != "" {
		session = session.Where("v5 = ?", fieldValues[5-fieldIndex])
	}
	_, err = session.Delete()
	return
}

func (a *Adapter) ensureTable() {
	_, err := a.engine.Exec(fmt.Sprintf("SELECT 1 FROM `%s` LIMIT 1", a.tableName))
	if err != nil {
		panic(err)
	}
}

func (a *Adapter) cleanTable() {
	_, err := a.engine.Exec(fmt.Sprintf("DELETE FROM `%s`", a.tableName))
	if err != nil {
		panic(err)
	}
}

// 仅加载与过滤器匹配的策略规则
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	filterValue, ok := filter.(Filter)
	if !ok {
		return errors.New("invalid filter type")
	}

	fvs := [7]struct {
		col string
		val []string
	}{
		{"p_type", filterValue.PType},
		{"v0", filterValue.V0},
		{"v1", filterValue.V1},
		{"v2", filterValue.V2},
		{"v3", filterValue.V3},
		{"v4", filterValue.V4},
		{"v5", filterValue.V5},
	}
	session := a.engine.Table(a.tableName)
	for idx := range fvs {
		switch len(fvs[idx].val) {
		case 0:
			continue
		case 1:
			session = session.Where(fvs[idx].col+" = ?", fvs[idx].val[0])
		default:
			session = session.Where(fvs[idx].col+" in (?)", fvs[idx].val)
		}
	}

	rules := make([]*CasbinRule, 0, 64)
	if err := session.Find(&rules); err != nil {
		return err
	}

	for _, rule := range rules {
		loadPolicyRuleLine(rule, model)
	}

	a.isFiltered = true
	return nil
}

func (a *Adapter) IsFiltered() bool {
	return a.isFiltered
}

func loadPolicyRuleLine(rule *CasbinRule, model model.Model) {
	var p = []string{rule.PType, rule.V0, rule.V1, rule.V2, rule.V3, rule.V4, rule.V5}
	var ruleText string
	if rule.V5 != "" {
		ruleText = strings.Join(p, ", ")
	} else if rule.V4 != "" {
		ruleText = strings.Join(p[:6], ", ")
	} else if rule.V3 != "" {
		ruleText = strings.Join(p[:5], ", ")
	} else if rule.V2 != "" {
		ruleText = strings.Join(p[:4], ", ")
	} else if rule.V1 != "" {
		ruleText = strings.Join(p[:3], ", ")
	} else if rule.V0 != "" {
		ruleText = strings.Join(p[:2], ", ")
	}

	persist.LoadPolicyLine(ruleText, model)
}

func genPolicyRuleLine(pType string, rules []string) *CasbinRule {
	line := CasbinRule{PType: pType}
	ruleLen := len(rules)
	if ruleLen > 0 {
		line.V0 = rules[0]
	}
	if ruleLen > 1 {
		line.V1 = rules[1]
	}
	if ruleLen > 2 {
		line.V2 = rules[2]
	}
	if ruleLen > 3 {
		line.V3 = rules[3]
	}
	if ruleLen > 4 {
		line.V4 = rules[4]
	}
	if ruleLen > 5 {
		line.V5 = rules[5]
	}

	return &line
}
