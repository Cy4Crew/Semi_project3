from pydantic import BaseModel, Field


class TargetCreate(BaseModel):
    value: str = Field(min_length=1, max_length=255)
    label: str = ""
    criticality: int = Field(default=3, ge=1, le=5)
