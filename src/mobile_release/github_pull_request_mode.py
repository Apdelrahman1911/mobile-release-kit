"""Closed PR creation mode; legacy absence is Draft, never Ready consent."""
from enum import Enum


class Mode(Enum):
    DRAFT = "draft"
    READY = "ready-for-review"


def parse(value: dict) -> Mode:
    if type(value) is not dict:
        raise ValueError("Invalid PR creation mode")
    if "creationMode" not in value:
        return Mode.DRAFT
    if type(value["creationMode"]) is str and value["creationMode"] == Mode.READY.value:
        return Mode.READY
    raise ValueError("Invalid PR creation mode")


def fields(mode: Mode) -> dict:
    if mode is Mode.DRAFT:
        return {}
    if mode is Mode.READY:
        return {"creationMode": Mode.READY.value}
    raise ValueError("Invalid PR creation mode")
