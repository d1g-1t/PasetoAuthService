import uuid

from paseto_forge.exceptions import UserNotFoundError
from paseto_forge.models.user import User
from paseto_forge.repositories.user_repo import UserRepository


class UserService:
    def __init__(self, user_repo: UserRepository):
        self.repo = user_repo

    async def get_by_id(self, user_id: uuid.UUID) -> User:
        user = await self.repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()
        return user

    async def get_by_email(self, email: str) -> User:
        user = await self.repo.get_by_email(email)
        if not user:
            raise UserNotFoundError()
        return user
