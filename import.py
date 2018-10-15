from fingerprints import cmstypes
from sqlalchemy import Column, String, Integer,create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

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


engine=create_engine("mysql+mysqlconnector://root:mlt98166@localhost:3306/fingerprints")

DBSession=sessionmaker(bind=engine)

session=DBSession()

for cms in cmstypes:
    for fullmark in cms['urls']:
        new_record=FingerPrints()
        new_record.type="hash"
        new_record.addr=fullmark['addr']
        new_record.pattern=fullmark['md5']
        new_record.exist_mark=fullmark['existMark']
        new_record.full_mark=fullmark['fullMark']
        new_record.cms=cms['name']
        session.add(new_record)
        session.commit()
    for content in cms['content']:
        new_record=FingerPrints()
        new_record.type="content"
        new_record.addr=content['addr']
        new_record.pattern=content['data']
        new_record.exist_mark=0
        new_record.full_mark=content['Mark']*3
        new_record.cms=cms['name']
        session.add(new_record)
        session.commit()

print "[+]all data writed"
session.close()