package sqlmigration

import (
	"context"

	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/sqlschema"
	"github.com/SigNoz/signoz/pkg/sqlstore"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/migrate"
)

type addServiceAccountOIDCBinding struct{ schema sqlschema.SQLSchema }

func NewAddServiceAccountOIDCBindingFactory(_ sqlstore.SQLStore, schema sqlschema.SQLSchema) factory.ProviderFactory[SQLMigration, Config] {
	return factory.NewProviderFactory(factory.MustNewName("add_sa_oidc_binding"), func(context.Context, factory.ProviderSettings, Config) (SQLMigration, error) {
		return &addServiceAccountOIDCBinding{schema: schema}, nil
	})
}

func (m *addServiceAccountOIDCBinding) Register(migrations *migrate.Migrations) error {
	return migrations.Register(m.Up, m.Down)
}

func (m *addServiceAccountOIDCBinding) Up(ctx context.Context, db *bun.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	sqls := m.schema.Operator().CreateTable(&sqlschema.Table{
		Name: "service_account_oidc_binding",
		Columns: []*sqlschema.Column{
			{Name: "service_account_id", DataType: sqlschema.DataTypeText, Nullable: false},
			{Name: "org_id", DataType: sqlschema.DataTypeText, Nullable: false},
			{Name: "issuer", DataType: sqlschema.DataTypeText, Nullable: false},
			{Name: "client_id", DataType: sqlschema.DataTypeText, Nullable: false},
			{Name: "subject", DataType: sqlschema.DataTypeText, Nullable: false},
		},
		PrimaryKeyConstraint: &sqlschema.PrimaryKeyConstraint{ColumnNames: []sqlschema.ColumnName{"service_account_id"}},
		ForeignKeyConstraints: []*sqlschema.ForeignKeyConstraint{
			{ReferencingColumnName: "service_account_id", ReferencedTableName: "service_account", ReferencedColumnName: "id"},
			{ReferencingColumnName: "org_id", ReferencedTableName: "organizations", ReferencedColumnName: "id"},
		},
	})
	for _, columns := range [][]sqlschema.ColumnName{{"issuer", "subject"}, {"issuer", "client_id"}} {
		sqls = append(sqls, m.schema.Operator().CreateIndex(&sqlschema.UniqueIndex{TableName: "service_account_oidc_binding", ColumnNames: columns})...)
	}
	for _, statement := range sqls {
		if _, err := tx.ExecContext(ctx, string(statement)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (m *addServiceAccountOIDCBinding) Down(context.Context, *bun.DB) error { return nil }
