import hashlib,secrets,time,os
from fastapi import Request,HTTPException,Depends
from .database.models import Session,User,LoginSession

def password_hash(password,salt=None):
    salt=salt or secrets.token_hex(16)
    return salt+':'+hashlib.scrypt(password.encode(),salt=salt.encode(),n=16384,r=8,p=1).hex()
def verify(password,stored):return secrets.compare_digest(password_hash(password,stored.split(':')[0]),stored)
def session_hash(token):return hashlib.sha256(token.encode()).hexdigest()
def current(request:Request):
    token=request.cookies.get('sentinel_session','')
    with Session() as db:
        s=db.get(LoginSession,session_hash(token))
        if not s or s.expires<time.time():raise HTTPException(401,'Please sign in')
        if request.method not in ['GET','HEAD','OPTIONS'] and not secrets.compare_digest(request.headers.get('x-csrf-token',''),s.csrf):raise HTTPException(403,'CSRF token missing or invalid')
        u=db.get(User,s.user_id)
        if not u:raise HTTPException(401,'Unknown user')
        return u
def editor(u=Depends(current)):
    if u.role not in ['admin','analyst']:raise HTTPException(403,'Analyst role required')
    return u
def admin(u=Depends(current)):
    if u.role!='admin':raise HTTPException(403,'Administrator role required')
    return u
