package sqlmigration

import (
	"context"

	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/sqlschema"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/migrate"
)

type addOIDCSessionRevocation struct{ schema sqlschema.SQLSchema }

func NewAddOIDCSessionRevocationFactory(schema sqlschema.SQLSchema) factory.ProviderFactory[SQLMigration, Config] {
	return factory.NewProviderFactory(factory.MustNewName("add_oidc_session_revocation"), func(context.Context, factory.ProviderSettings, Config) (SQLMigration, error) {
		return &addOIDCSessionRevocation{schema: schema}, nil
	})
}

func (m *addOIDCSessionRevocation) Register(migrations *migrate.Migrations) error {
	return migrations.Register(m.Up, m.Down)
}

func (m *addOIDCSessionRevocation) Up(ctx context.Context, db *bun.DB) error {
	for _, statement := range m.schema.Operator().CreateTable(&sqlschema.Table{
		Name: "oidc_session_revocation",
		Columns: []*sqlschema.Column{
			{Name: "id", DataType: sqlschema.DataTypeText, Nullable: false},
			{Name: "issued_at", DataType: sqlschema.DataTypeBigInt, Nullable: false},
		},
		PrimaryKeyConstraint: &sqlschema.PrimaryKeyConstraint{ColumnNames: []sqlschema.ColumnName{"id"}},
	}) {
		if _, err := db.ExecContext(ctx, string(statement)); err != nil {
			return err
		}
	}
	return nil
}

func (m *addOIDCSessionRevocation) Down(context.Context, *bun.DB) error { return nil }
