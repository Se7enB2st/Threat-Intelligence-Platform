"""remove last_update from shodan_data

Revision ID: remove_last_update
Revises: 
Create Date: 2024-03-21 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime

# revision identifiers, used by Alembic.
revision = 'remove_last_update'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Remove the last_update column from shodan_data table
    op.drop_column('shodan_data', 'last_update')

def downgrade():
    # Add back the last_update column
    op.add_column('shodan_data',
        sa.Column('last_update', sa.DateTime(), nullable=True)
    ) 