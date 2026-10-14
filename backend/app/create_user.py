import argparse,getpass
from .database.models import Session,User
from .auth import password_hash
p=argparse.ArgumentParser();p.add_argument('username');p.add_argument('--role',choices=['admin','analyst','viewer'],default='analyst');args=p.parse_args()
pw=getpass.getpass('New password (12+ characters): ')
if len(pw)<12:raise SystemExit('Password too short')
with Session() as db:db.add(User(username=args.username,password=password_hash(pw),role=args.role));db.commit()
print('User created.')
