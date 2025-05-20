"""Add cascade delete for reports

Revision ID: 5117d768e9d0
Revises: a9217effbc2d
Create Date: 2025-05-20 14:08:27.949195

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5117d768e9d0'
down_revision = 'a9217effbc2d'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('feedback', schema=None) as batch_op:
        batch_op.drop_column('resolved')

    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.alter_column('reason',
               existing_type=sa.VARCHAR(length=200),
               type_=sa.Text(),
               existing_nullable=False)
        # Removed drop_constraint(None, ...)
        batch_op.create_foreign_key(
            'fk_report_item_id', 'lost_item', ['item_id'], ['id'], ondelete='CASCADE'
        )
        batch_op.drop_column('resolved')


def downgrade():
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.add_column(sa.Column('resolved', sa.BOOLEAN(), nullable=True))
        batch_op.drop_constraint('fk_report_item_id', type_='foreignkey')
        batch_op.create_foreign_key(
            'fk_report_item_id', 'lost_item', ['item_id'], ['id']
        )
        batch_op.alter_column('reason',
               existing_type=sa.Text(),
               type_=sa.VARCHAR(length=200),
               existing_nullable=False)

    with op.batch_alter_table('feedback', schema=None) as batch_op:
        batch_op.add_column(sa.Column('resolved', sa.BOOLEAN(), nullable=True))
