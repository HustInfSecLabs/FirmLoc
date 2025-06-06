from enum import Enum


class ProgressEnum(int, Enum):
    """
    Enum for progress status.
    """
    FAILED = -1
    NOT_STARTED = 0
    USER_AGENT = 1
    PLANNER_AGENT = 2
    BINWALKAGENT = 3
    IDAAGENT = 4
    BINDIFFAGENT = 5
    LOCATIONAGENT = 6
    DETECTIONAGENT = 7
    COMPLETED = 8
    RUNNING = 9


class TaskStatusEnum(int, Enum):
    """
    Enum for task status.
    """
    NOT_STARTED = 0
    IN_PROGRESS = 1
    COMPLETED = 2
    FAILED = 3