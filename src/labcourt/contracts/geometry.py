"""Geometry value objects with closed-open pixel semantics."""

from __future__ import annotations

from typing import Annotated, TypeAlias

from pydantic import BeforeValidator, Field, model_validator

from labcourt.contracts.base import FrozenContractModel


class PointXY(FrozenContractModel):
    x: int = Field(ge=0, strict=True)
    y: int = Field(ge=0, strict=True)

    @model_validator(mode="before")
    @classmethod
    def accept_coordinate_pair(cls, value: object) -> object:
        if isinstance(value, (list, tuple)) and len(value) == 2:
            return {"x": value[0], "y": value[1]}
        return value


PointInput: TypeAlias = Annotated[
    PointXY,
    BeforeValidator(
        lambda value: (
            {"x": value[0], "y": value[1]}
            if isinstance(value, (list, tuple)) and len(value) == 2
            else value
        ),
        json_schema_input_type=PointXY | tuple[int, int],
    ),
]


class BBoxXYXY(FrozenContractModel):
    """Integer `[x1, y1, x2, y2)` bounding box."""

    x1: int = Field(ge=0, strict=True)
    y1: int = Field(ge=0, strict=True)
    x2: int = Field(gt=0, strict=True)
    y2: int = Field(gt=0, strict=True)

    @model_validator(mode="after")
    def validate_order(self) -> BBoxXYXY:
        if self.x1 >= self.x2 or self.y1 >= self.y2:
            raise ValueError("bbox must satisfy x1 < x2 and y1 < y2")
        return self

    @property
    def width(self) -> int:
        return self.x2 - self.x1

    @property
    def height(self) -> int:
        return self.y2 - self.y1

    @property
    def area(self) -> int:
        return self.width * self.height

    def is_within(self, width: int, height: int) -> bool:
        return self.x2 <= width and self.y2 <= height

    def require_within(self, width: int, height: int) -> BBoxXYXY:
        if not self.is_within(width, height):
            raise ValueError(f"bbox exceeds frame bounds {width}x{height}")
        return self

    def clipped(self, width: int, height: int) -> BBoxXYXY:
        if width <= 0 or height <= 0:
            raise ValueError("frame dimensions must be positive")
        x1 = min(self.x1, width - 1)
        y1 = min(self.y1, height - 1)
        x2 = max(x1 + 1, min(self.x2, width))
        y2 = max(y1 + 1, min(self.y2, height))
        return BBoxXYXY(x1=x1, y1=y1, x2=x2, y2=y2)

    def intersection_area(self, other: BBoxXYXY) -> int:
        width = max(0, min(self.x2, other.x2) - max(self.x1, other.x1))
        height = max(0, min(self.y2, other.y2) - max(self.y1, other.y1))
        return width * height

    def iou(self, other: BBoxXYXY) -> float:
        intersection = self.intersection_area(other)
        if intersection == 0:
            return 0.0
        return intersection / (self.area + other.area - intersection)


class Polygon(FrozenContractModel):
    points: tuple[PointInput, ...] = Field(min_length=3)

    @model_validator(mode="before")
    @classmethod
    def accept_coordinate_pairs(cls, value: object) -> object:
        if isinstance(value, (list, tuple)):
            return {"points": value}
        return value

    @model_validator(mode="after")
    def reject_degenerate_polygon(self) -> Polygon:
        if len(set(self.points)) != len(self.points):
            raise ValueError("polygon points must be distinct")
        twice_area = 0
        for index, point in enumerate(self.points):
            following = self.points[(index + 1) % len(self.points)]
            twice_area += point.x * following.y - following.x * point.y
        if twice_area == 0:
            raise ValueError("polygon must have non-zero area")
        return self


PolygonInput: TypeAlias = Annotated[
    Polygon,
    BeforeValidator(
        lambda value: {"points": value} if isinstance(value, (list, tuple)) else value,
        json_schema_input_type=Polygon | list[tuple[int, int]],
    ),
]
