from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key = True)
    name = Column(String(250), nullable = False)
    email = Column(String(250), nullable = False)
    picture = Column(String(250))

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'id'         : self.id,
           'name'         : self.name,
           'email'         : self.email,
           'picture'         : self.picture,
       }

 
class MenuItem(Base):
    __tablename__ = 'menu_item'


    name =Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    category = Column(String(25))
    description = Column(String(250))
    price = Column(String(8))
    user_id = Column(Integer, ForeignKey('user.id'))  
    user = relationship(User)                         

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'description'         : self.description,
           'category'         : self.category,
           'id'         : self.id,
           'price'         : self.price,
           
       }


engine = create_engine('sqlite:///virtualvendingmachine.db')
 

Base.metadata.create_all(engine)
