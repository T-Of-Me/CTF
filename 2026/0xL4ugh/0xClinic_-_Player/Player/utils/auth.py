import inspect
import jwt
from datetime import datetime
from fastapi import Request, HTTPException
from functools import wraps
    
    
def create_token(user: dict,JWT_SECRET) -> str:
    """Create a new token for a user"""
    print("create:"+JWT_SECRET)
    token = jwt.encode(
        {   
            "id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "verified": user["verified"],
            "iat": datetime.utcnow().timestamp()
        },
        JWT_SECRET,
        algorithm="HS256"
    )
    return token
    
def require_auth(JWT_SECRET: str):
    def decorator(fn):
        @wraps(fn)
        async def wrapper(request: Request, *args, **kwargs):
            print("require: " + JWT_SECRET)
            token = request.cookies.get("auth")
            if not token:
                raise HTTPException(status_code=401, detail="Missing token")
            
            try:
                request.state.user = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            except Exception as e:
                raise HTTPException(status_code=401, detail=str(e))
            result = fn(request, *args, **kwargs)

            if inspect.isawaitable(result):
                return await result
            return result
        return wrapper
    return decorator