from sqlalchemy import Column, String, Integer,create_engine,func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.pool import NullPool


Base=declarative_base()

class FingerPrints(Base):
    __tablename__='fingerprints'

    id=Column(Integer,primary_key=True)
    type=Column(String(10))
    addr=Column(String(255))
    pattern=Column(String(255))
    exist_mark=Column(Integer)
    full_mark=Column(Integer)
    cms=Column(String(255))


engine=create_engine("mysql+mysqlconnector://root:mlt98166@localhost:3306/fingerprints", poolclass=NullPool)

DBSession=sessionmaker(bind=engine)

