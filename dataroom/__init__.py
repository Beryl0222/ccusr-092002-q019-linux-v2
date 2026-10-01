"""跨境药研受控资料室。

按交易隔离的尽调资料室：分级授权、即时撤权、内容指纹与脱敏谱系、
唯一水印、事件持久化处置、受限问答双审与竞标方浏览轨迹复原。
"""

from .app import DataRoom
from .errors import DataRoomError

__all__ = ["DataRoom", "DataRoomError"]
