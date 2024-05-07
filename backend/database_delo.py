from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Float, Boolean, UUID
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, DeclarativeBase
import uuid
from datetime import datetime


engine = create_engine("postgresql://admin:admin@db:5432/cleanDataset")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base: DeclarativeBase = declarative_base()


class Uporabniki(Base):
    __tablename__ = "users_tabela"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, index=True, unique=True)
    password = Column(String)
    email = Column(String, unique=True)
    role = Column(String)


class OpravilaSeznam(Base):
    __tablename__ = "opravila_tabela"
    id_opravilo = Column(String, primary_key=True)
    evidenca = relationship("Evidenca", back_populates="opravila")


class CistilaSeznam(Base):
    __tablename__ = "cistila_tabela"
    id_cistilo = Column(String, primary_key=True)
    sredstva = relationship("Sredstva", back_populates="cistila")


class Sredstva(Base):
    __tablename__ = "sredstva_tabela"
    id_sredstva = Column(Integer, primary_key=True, autoincrement=True)
    user_username = Column(String)
    cistilo = Column(String, ForeignKey("cistila_tabela.id_cistilo"))
    cistila = relationship("CistilaSeznam", back_populates="sredstva")
    stevilo = Column(Integer)
    denar = Column(Float)
    date = Column(DateTime, default=datetime.utcnow)


class Evidenca(Base):
    __tablename__ = "evidenca_tabela"
    id_evidenca = Column(Integer, primary_key=True, autoincrement=True)
    user_username = Column(String)
    done = Column(Boolean)
    datum = Column(DateTime, default=datetime.utcnow)
    opravilo = Column(String, ForeignKey("opravila_tabela.id_opravilo"))
    opravila = relationship("OpravilaSeznam", back_populates="evidenca")


class ResetToken(Base):
    __tablename__ = "reset_tokens"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token = Column(String)
    expiration_time = Column(DateTime)
    user_username = Column(String)


Base.metadata.create_all(engine)
