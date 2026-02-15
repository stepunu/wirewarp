from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.service_template import ServiceTemplate
from app.models.user import User
from app.schemas.service_template import ServiceTemplateCreate, ServiceTemplateRead
from app.auth import get_current_user

router = APIRouter()

BUILTIN_TEMPLATES = [
    {"name": "DayZ", "protocol": "udp", "ports": "2302-2305,27016"},
    {"name": "Minecraft", "protocol": "tcp", "ports": "25565"},
    {"name": "Web", "protocol": "tcp", "ports": "80,443"},
    {"name": "RDP", "protocol": "tcp", "ports": "3389"},
]


async def seed_builtin_templates(db: AsyncSession) -> None:
    for tmpl in BUILTIN_TEMPLATES:
        result = await db.execute(select(ServiceTemplate).where(ServiceTemplate.name == tmpl["name"]))
        if not result.scalar_one_or_none():
            db.add(ServiceTemplate(**tmpl, is_builtin=True))
    await db.commit()


@router.get("", response_model=list[ServiceTemplateRead])
async def list_templates(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    await seed_builtin_templates(db)
    result = await db.execute(select(ServiceTemplate).order_by(ServiceTemplate.name))
    return result.scalars().all()


@router.post("", response_model=ServiceTemplateRead, status_code=201)
async def create_template(
    body: ServiceTemplateCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(ServiceTemplate).where(ServiceTemplate.name == body.name))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Template name already exists")
    tmpl = ServiceTemplate(**body.model_dump(), is_builtin=False)
    db.add(tmpl)
    await db.commit()
    await db.refresh(tmpl)
    return tmpl
