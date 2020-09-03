package sqldbadapter_test

import (
	"io/ioutil"
	"log"
	"testing"

	"github.com/binwen/sqldb"
	_ "github.com/binwen/sqldb/dialects/mysql"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"

	sqldbadapter "github.com/binwen/casbin-sqldb-adapter"
)

var (
	driverName = "mysql"
	driverDNS  = "root:@/kuiba?charset=utf8&parseTime=True"
)

func setupDB(t *testing.T) {
	sql, err := ioutil.ReadFile("examples/casbin_rule.sql")
	if err != nil {
		t.Fatalf("failed to load casbin_rule sql migration: %s", err)
	}
	engine, err := sqldb.OpenSingleDBEngine(&sqldb.Config{Driver: driverName, DNS: driverDNS}, false)
	if err != nil {
		t.Fatalf("failed to connect to database: %s", err)
	}
	defer engine.Close()
	_, err = engine.Exec(string(sql))
	if err != nil {
		t.Fatalf("failed to run casbin_rule sql migration: %s", err)
	}
}

func testGetPolicy(t *testing.T, enforcer *casbin.Enforcer, res [][]string) {
	t.Helper()
	myRes := enforcer.GetPolicy()
	log.Print("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func initPolicy(t *testing.T) {
	var err error
	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	adapter := sqldbadapter.NewAdapter(driverName, driverDNS)
	err = adapter.SavePolicy(enforcer.GetModel())
	if err != nil {
		panic(err)
	}
	enforcer.ClearPolicy()
	testGetPolicy(t, enforcer, [][]string{})
	err = adapter.LoadPolicy(enforcer.GetModel())
	if err != nil {
		panic(err)
	}
	testGetPolicy(
		t,
		enforcer,
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
		},
	)
}

func testSaveLoad(t *testing.T) {
	initPolicy(t)
	adapter := sqldbadapter.NewAdapter(driverName, driverDNS)
	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}
	testGetPolicy(
		t,
		enforcer,
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
		},
	)
}

func testAutoSave(t *testing.T) {
	initPolicy(t)
	adapter := sqldbadapter.NewAdapter(driverName, driverDNS)
	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}
	enforcer.EnableAutoSave(false)
	_, _ = enforcer.AddPolicy("alice", "data1", "write")
	_ = enforcer.LoadPolicy()
	testGetPolicy(
		t, enforcer,
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
		},
	)

	enforcer.EnableAutoSave(true)
	_, _ = enforcer.AddPolicy("alice", "data1", "write")
	_ = enforcer.LoadPolicy()
	testGetPolicy(
		t, enforcer,
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
			{"alice", "data1", "write"},
		},
	)
	_, _ = enforcer.RemovePolicy("alice", "data1", "write")
	_ = enforcer.LoadPolicy()
	testGetPolicy(
		t, enforcer,
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
		},
	)
	_, _ = enforcer.RemoveFilteredPolicy(0, "data2_admin")
	_ = enforcer.LoadPolicy()
	testGetPolicy(
		t, enforcer,
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}},
	)

}

func testFilteredPolicy(t *testing.T) {
	initPolicy(t)
	adapter := sqldbadapter.NewAdapter(driverName, driverDNS)
	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf")
	if err != nil {
		t.Fatal(err)
	}
	enforcer.SetAdapter(adapter)

	if err := enforcer.LoadFilteredPolicy(sqldbadapter.Filter{V0: []string{"alice"}}); err != nil {
		t.Fatal(err)
	}
	testGetPolicy(t, enforcer, [][]string{{"alice", "data1", "read"}})

	if err := enforcer.LoadFilteredPolicy(sqldbadapter.Filter{V0: []string{"bob"}}); err != nil {
		t.Fatal(err)
	}
	testGetPolicy(t, enforcer, [][]string{{"bob", "data2", "write"}})

	if err := enforcer.LoadFilteredPolicy(sqldbadapter.Filter{V0: []string{"data2_admin"}}); err != nil {
		t.Fatal(err)
	}
	testGetPolicy(t, enforcer, [][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	if err := enforcer.LoadFilteredPolicy(sqldbadapter.Filter{V0: []string{"alice", "bob"}}); err != nil {
		t.Fatal(err)
	}
	testGetPolicy(t, enforcer, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
}

func testBulkAddPolicy(t *testing.T) {
	initPolicy(t)
	adapter := sqldbadapter.NewAdapter(driverName, driverDNS)
	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.BulkAddPolicy("p", "p", [][]string{{"max", "data2", "read"}, {"max", "data1", "write"}}); err != nil {
		t.Fatal(err)
	}
	if err := enforcer.LoadFilteredPolicy(sqldbadapter.Filter{V0: []string{"max"}}); err != nil {
		t.Fatal(err)
	}
	testGetPolicy(t, enforcer, [][]string{{"max", "data2", "read"}, {"max", "data1", "write"}})
}

func testBulkRemovePolicy(t *testing.T) {
	initPolicy(t)
	adapter := sqldbadapter.NewAdapter(driverName, driverDNS)
	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}

	if err := adapter.BulkAddPolicy(
		"p",
		"p",
		[][]string{
			{"max", "data2", "read"},
			{"max", "data1", "write"},
			{"max", "data1", "delete"},
		}); err != nil {
		t.Fatal(err)
	}
	if err := enforcer.LoadFilteredPolicy(sqldbadapter.Filter{V0: []string{"max"}}); err != nil {
		t.Fatal(err)
	}
	testGetPolicy(
		t, enforcer,
		[][]string{
			{"max", "data2", "read"},
			{"max", "data1", "write"},
			{"max", "data1", "delete"},
		},
	)

	if err := adapter.BulkRemovePolicy(
		"p",
		"p",
		[][]string{{"max", "data2", "read"}, {"max", "data1", "write"}},
	); err != nil {
		t.Fatal(err)
	}
	if err := enforcer.LoadFilteredPolicy(sqldbadapter.Filter{V0: []string{"max"}}); err != nil {
		t.Fatal(err)
	}
	testGetPolicy(t, enforcer, [][]string{{"max", "data1", "delete"}})
}

func TestAdapters(t *testing.T) {
	setupDB(t)
	testFilteredPolicy(t)
	testSaveLoad(t)
	testAutoSave(t)
	testBulkAddPolicy(t)
	testBulkRemovePolicy(t)
}
