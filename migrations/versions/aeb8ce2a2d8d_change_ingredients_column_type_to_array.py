"""Change Ingredients column type to ARRAY

Revision ID: aeb8ce2a2d8d
Revises: a3f82ea4baea
Create Date: 2023-11-22 18:11:08.213456

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'aeb8ce2a2d8d'
down_revision = 'a3f82ea4baea'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('dishview', schema=None) as batch_op:
        batch_op.alter_column('Ingredients',
               existing_type=postgresql.BYTEA(),
               type_=postgresql.ARRAY(sa.String()),
               existing_nullable=False)
        batch_op.alter_column('dish_image_url',
               existing_type=sa.VARCHAR(length=255),
               type_=sa.LargeBinary(),
               existing_nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('dishview', schema=None) as batch_op:
        batch_op.alter_column('dish_image_url',
               existing_type=sa.LargeBinary(),
               type_=sa.VARCHAR(length=255),
               existing_nullable=False)
        batch_op.alter_column('Ingredients',
               existing_type=postgresql.ARRAY(sa.String()),
               type_=postgresql.BYTEA(),
               existing_nullable=False)

    # ### end Alembic commands ###