import getpass
from sqlalchemy import select
from .database.models import Session,User
from .auth import password_hash
with Session() as db:
    if db.scalar(select(User).limit(1)):
        print('Existing accounts found. Sign in with your existing credentials.')
    else:
        username=input('Choose admin username: ').strip()
        pw=getpass.getpass('Choose password (12+ characters): ')
        confirm=getpass.getpass('Repeat password: ')
        if not username or len(pw)<12 or pw!=confirm:raise SystemExit('Invalid username, short password or mismatch. Run setup again.')
        db.add(User(username=username,password=password_hash(pw),role='admin'));db.commit();print('Administrator created.')
