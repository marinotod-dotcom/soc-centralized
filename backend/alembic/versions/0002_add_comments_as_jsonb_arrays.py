import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vulnerability_tracking",
        sa.Column(
            "validation_comment",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
    )

    op.alter_column(
        "vulnerability_tracking",
        "treatment_comment",
        type_=postgresql.JSONB(astext_type=sa.Text()),
        postgresql_using=(
            "CASE "
            "WHEN treatment_comment IS NULL OR treatment_comment = '' "
            "THEN '[]'::jsonb "
            "ELSE jsonb_build_array(treatment_comment) END"
        ),
        server_default="[]",
        nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "vulnerability_tracking",
        "treatment_comment",
        type_=sa.Text(),
        postgresql_using="treatment_comment->>0",
        server_default=None,
        nullable=True,
    )
    op.drop_column("vulnerability_tracking", "validation_comment")