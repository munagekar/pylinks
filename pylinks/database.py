import databases
import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base

DATABASE_URL = "sqlite:///data/test.db"
database = databases.Database(DATABASE_URL)

metadata = sqlalchemy.MetaData()
engine = sqlalchemy.create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

Base = declarative_base()
metadata.create_all(engine)
