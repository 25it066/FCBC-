import os,uuid,time
from sqlalchemy import create_engine, String, Text, JSON, Float, Integer, ForeignKey, event
from sqlalchemy.orm import DeclarativeBase,Mapped,mapped_column,sessionmaker

def uid():return uuid.uuid4().hex
class Base(DeclarativeBase):pass
class User(Base):
    __tablename__='users'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    username:Mapped[str]=mapped_column(String,unique=True)
    password:Mapped[str]=mapped_column(Text)
    role:Mapped[str]=mapped_column(String,default='analyst')
    settings:Mapped[dict]=mapped_column(JSON,default=dict)
class LoginSession(Base):
    __tablename__='login_sessions'
    id:Mapped[str]=mapped_column(String,primary_key=True)
    user_id:Mapped[str]=mapped_column(ForeignKey('users.id'),index=True)
    csrf:Mapped[str]=mapped_column(String)
    expires:Mapped[float]=mapped_column(Float)
class Dataset(Base):
    __tablename__='datasets'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    owner:Mapped[str]=mapped_column(ForeignKey('users.id'),index=True)
    name:Mapped[str]=mapped_column(String)
    sha256:Mapped[str]=mapped_column(String)
    count:Mapped[int]=mapped_column(Integer)
    synthetic:Mapped[int]=mapped_column(Integer,default=0)
    context:Mapped[dict|None]=mapped_column(JSON,nullable=True)
    created:Mapped[float]=mapped_column(Float,default=time.time)
class FileEvent(Base):
    __tablename__='file_events'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    dataset_id:Mapped[str]=mapped_column(ForeignKey('datasets.id',ondelete='CASCADE'),index=True)
    data:Mapped[dict]=mapped_column(JSON)
class Run(Base):
    __tablename__='analysis_runs'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    dataset_id:Mapped[str]=mapped_column(ForeignKey('datasets.id',ondelete='CASCADE'),index=True)
    owner:Mapped[str]=mapped_column(ForeignKey('users.id'),index=True)
    status:Mapped[str]=mapped_column(String,default='queued')
    config:Mapped[dict]=mapped_column(JSON)
    result:Mapped[dict|None]=mapped_column(JSON,nullable=True)
    error:Mapped[str|None]=mapped_column(Text,nullable=True)
    created:Mapped[float]=mapped_column(Float,default=time.time)
class Episode(Base):
    __tablename__='file_episodes'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    run_id:Mapped[str]=mapped_column(ForeignKey('analysis_runs.id',ondelete='CASCADE'),index=True)
    data:Mapped[dict]=mapped_column(JSON)
class Window(Base):
    __tablename__='analysis_windows'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    run_id:Mapped[str]=mapped_column(ForeignKey('analysis_runs.id',ondelete='CASCADE'),index=True)
    data:Mapped[dict]=mapped_column(JSON)
class Alert(Base):
    __tablename__='threat_alerts'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    run_id:Mapped[str]=mapped_column(ForeignKey('analysis_runs.id',ondelete='CASCADE'),index=True)
    status:Mapped[str]=mapped_column(String,default='New')
    notes:Mapped[str]=mapped_column(Text,default='')
    data:Mapped[dict]=mapped_column(JSON)
class Review(Base):
    __tablename__='analyst_reviews'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    alert_id:Mapped[str]=mapped_column(ForeignKey('threat_alerts.id',ondelete='CASCADE'),index=True)
    actor:Mapped[str]=mapped_column(ForeignKey('users.id'))
    data:Mapped[dict]=mapped_column(JSON)
    created:Mapped[float]=mapped_column(Float,default=time.time)
class Evaluation(Base):
    __tablename__='evaluation_experiments'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    owner:Mapped[str]=mapped_column(ForeignKey('users.id'),index=True)
    data:Mapped[dict]=mapped_column(JSON)
    created:Mapped[float]=mapped_column(Float,default=time.time)
class Audit(Base):
    __tablename__='audit_logs'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    actor:Mapped[str]=mapped_column(String,index=True)
    action:Mapped[str]=mapped_column(String)
    target:Mapped[str]=mapped_column(String)
    created:Mapped[float]=mapped_column(Float,default=time.time)
url=os.getenv('DATABASE_URL','sqlite:///./sentinel.db')
engine=create_engine(url,connect_args={'check_same_thread':False} if url.startswith('sqlite') else {})
if url.startswith('sqlite'):
    @event.listens_for(engine,'connect')
    def pragmas(connection,_):
        connection.execute('PRAGMA foreign_keys=ON');connection.execute('PRAGMA journal_mode=WAL')
Session=sessionmaker(engine,expire_on_commit=False)
