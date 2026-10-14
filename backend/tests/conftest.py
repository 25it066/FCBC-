import os,tempfile
os.environ['DATABASE_URL']='sqlite:///'+tempfile.mktemp(suffix='.db')
os.environ['ADMIN_PASSWORD']='test-only-password-123'
os.environ['ADMIN_USERNAME']='admin'
import pytest
from app.database.models import Base,engine
from app.main import app,attempts
from fastapi.testclient import TestClient
@pytest.fixture
def client():
    Base.metadata.drop_all(engine);Base.metadata.create_all(engine);attempts.clear()
    with TestClient(app) as c:
        r=c.post('/api/auth/login',json={'username':'admin','password':'test-only-password-123'});assert r.status_code==200
        c.headers['x-csrf-token']=r.json()['csrf'];yield c
