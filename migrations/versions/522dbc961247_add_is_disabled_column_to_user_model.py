"""Add is_disabled column to user model

Revision ID: 522dbc961247
Revises: 5117d768e9d0
Create Date: 2025-05-20 14:37:23.707850

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '522dbc961247'
down_revision = '5117d768e9d0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_disabled', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('is_disabled')

    # ### end Alembic commands ###
