from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.system_settings import SystemSettings
from app.models.user import User
from app.schemas.system_settings import SystemSettingsRead, SystemSettingsUpdate
from app.auth import get_current_user

router = APIRouter()


async def _get_or_create(db: AsyncSession) -> SystemSettings:
    row = await db.get(SystemSettings, 1)
    if not row:
        row = SystemSettings(id=1)
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return row


@router.get("", response_model=SystemSettingsRead)
async def get_settings(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    return await _get_or_create(db)


@router.patch("", response_model=SystemSettingsRead)
async def update_settings(
    body: SystemSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    row = await _get_or_create(db)
    for field, val in body.model_dump(exclude_none=True).items():
        setattr(row, field, val)
    await db.commit()
    await db.refresh(row)
    return row
