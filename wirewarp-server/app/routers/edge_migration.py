import uuid

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_ops_role, require_role
from app.database import get_db
from app.models.edge_migration import EdgeMigration
from app.models.user import User
from app.schemas.edge_migration import EdgeMigrationAction, EdgeMigrationRequest, EdgeMigrationStageRequest
from app.services import edge_migration as ops

router = APIRouter()


@router.post("/preview")
async def preview(body: EdgeMigrationRequest, db: AsyncSession = Depends(get_db), _: User = Depends(require_ops_role)):
    return await ops.preview(db, body)


@router.get("")
async def list_migrations(db: AsyncSession = Depends(get_db), _: User = Depends(require_ops_role)):
    records = (await db.scalars(select(EdgeMigration).order_by(EdgeMigration.created_at.desc()))).all()
    return [await ops.migration_read(db, record) for record in records]


@router.post("", status_code=201)
async def stage(body: EdgeMigrationStageRequest, db: AsyncSession = Depends(get_db), actor: User = Depends(require_role("admin"))):
    return await ops.migration_read(db, await ops.stage(db, body, actor))


@router.get("/{migration_id}")
async def get_migration(migration_id: uuid.UUID, db: AsyncSession = Depends(get_db), _: User = Depends(require_ops_role)):
    return await ops.migration_read(db, await ops.get_migration(db, migration_id))


@router.post("/{migration_id}/provision")
async def provision(migration_id: uuid.UUID, body: EdgeMigrationAction, db: AsyncSession = Depends(get_db), actor: User = Depends(require_role("admin"))):
    record = await ops.get_migration(db, migration_id, body.revision)
    return await ops.migration_read(db, await ops.provision(db, record, actor))


@router.post("/{migration_id}/test")
async def test(migration_id: uuid.UUID, body: EdgeMigrationAction, db: AsyncSession = Depends(get_db), actor: User = Depends(require_role("admin"))):
    record = await ops.get_migration(db, migration_id, body.revision)
    return await ops.migration_read(db, await ops.test_route(db, record, actor))


@router.post("/{migration_id}/finalize")
async def finalize(migration_id: uuid.UUID, body: EdgeMigrationAction, db: AsyncSession = Depends(get_db), actor: User = Depends(require_role("admin"))):
    record = await ops.get_migration(db, migration_id, body.revision)
    return await ops.migration_read(db, await ops.finalize(db, record, actor))


@router.post("/{migration_id}/rollback")
async def rollback(migration_id: uuid.UUID, body: EdgeMigrationAction, db: AsyncSession = Depends(get_db), actor: User = Depends(require_role("admin"))):
    record = await ops.get_migration(db, migration_id, body.revision)
    return await ops.migration_read(db, await ops.rollback(db, record, actor))


@router.post("/{migration_id}/cancel")
async def cancel(migration_id: uuid.UUID, body: EdgeMigrationAction, db: AsyncSession = Depends(get_db), actor: User = Depends(require_role("admin"))):
    record = await ops.get_migration(db, migration_id, body.revision)
    return await ops.migration_read(db, await ops.cancel(db, record, actor))


@router.delete("/{migration_id}", status_code=204)
async def discard(migration_id: uuid.UUID, revision: int = Query(ge=1), db: AsyncSession = Depends(get_db), _: User = Depends(require_role("admin"))):
    record = await ops.get_migration(db, migration_id, revision)
    await ops.discard(db, record)
    return Response(status_code=204)
