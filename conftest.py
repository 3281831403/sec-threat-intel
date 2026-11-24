"""pytest 配置：确保仓库根目录在导入路径中，engine 嵌套布局才能被导入。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))