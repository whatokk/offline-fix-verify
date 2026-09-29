---
name: offline-fix-verify
description: 验证代码修复是否真的生效，并证明"修复前确实有漏洞、修复后确实修好"。当用户要求验收修复、验证安全或并发问题、跑通项目、或需要修复前后对照证据时使用。覆盖三层验证（框架桩 / 真实 HTTP / 完整闭环）与"装不上依赖"时的降级手法。触发词：验证修复、能不能跑通、验收、对照实验、漏洞验证、装不上依赖、pip 失败。
agent_created: true
---

# 验证代码修复（并证明修复有效）

## 何时用

- 修了安全问题（路径穿越、SSRF、鉴权绕过）或并发问题（事件循环阻塞、竞态），要拿出证据而不只是"我看了一遍代码"
- 用户问"这个能跑通吗"——需要真跑，而不是读代码下结论
- 环境装不上依赖（pip 超时、镜像 404、沙箱拦截）

## 验证分三层，按可得性逐层推进

| 层 | 手段 | 能证明什么 |
|---|---|---|
| 1 逻辑层 | `sys.modules` 注入框架桩，import 真实业务代码 | 业务逻辑、边界、安全校验 |
| 2 HTTP 层 | 真起 uvicorn，发真实请求 | 依赖注入、中间件、multipart、鉴权链路 |
| 3 闭环层 | 把外部上游指向**本地假服务** | 完整数据流（上传→处理→组包→调用→解析） |

**能装依赖就别只用桩**。桩是降级方案，不是终态——本轮实际路径是：先用桩拿到初步结论 → 后台慢慢把大 wheel 下完 → 用真依赖**零替身复跑全部验证**。

## 核心手法

### 1. 模块桩注入：不装框架也能跑真实业务代码

用 `sys.modules` 注入假框架模块，再 import 真实业务文件。**业务代码一行不改**。

```python
import sys, types

class HTTPException(Exception):
    def __init__(self, status_code=500, detail=""):
        super().__init__(detail)
        self.status_code, self.detail = status_code, detail

class _Stub:                      # Depends/File/Form/Header 通用占位
    def __init__(self, *a, **k): pass
    def __call__(self, *a, **k): return None

class _FakeApp:
    def __init__(self, *a, **k): pass          # 必须接受参数：FastAPI(title=...)
    def post(self, *a, **k): return lambda f: f
    def get(self, *a, **k):  return lambda f: f
    def middleware(self, *a, **k): return lambda f: f
    def add_middleware(self, *a, **k): return None
    def mount(self, *a, **k): return None

fastapi = types.ModuleType("fastapi")
fastapi.FastAPI, fastapi.HTTPException = _FakeApp, HTTPException
fastapi.Depends = fastapi.File = fastapi.Form = fastapi.Header = _Stub
fastapi.Request = fastapi.UploadFile = _Stub
sys.modules["fastapi"] = fastapi
# 同理注入 fastapi.middleware.cors / fastapi.staticfiles / starlette.concurrency

async def run_in_threadpool(fn, *a, **k): return fn(*a, **k)   # 桩成同步直调
```

端点函数保留原名（装饰器返回原函数），按参数名适配调用：

```python
import inspect
kwargs = {}
for name in inspect.signature(appmod.analyze).parameters:
    if name == "file":      kwargs[name] = FakeUpload(...)   # 同时实现 async read() 和 .file
    elif name == "request": kwargs[name] = FakeRequest()     # 要有 .client.host / .headers
    else:                   kwargs[name] = None
asyncio.run(appmod.analyze(**kwargs))
```

### 2. 替身设计原则：可以缺功能，不能返回假结果

装不上某个包时，**别写"返回假值的 shim"**——那会让后续验证失去意义。正确做法是让它只做「解析真实资源路径」，找不到就抛错：

```python
# 装不上 imageio-ffmpeg（31MB 下载不动）时的替代：只做路径解析
def get_ffmpeg_exe() -> str:
    for c in (os.environ.get("VI_FFMPEG"), shutil.which("ffmpeg"), *KNOWN_PATHS):
        if c and os.path.exists(c):
            return c
    raise FileNotFoundError("未找到可用的 ffmpeg；设置 VI_FFMPEG 或加入 PATH")
```

这样服务能起来，且**抽帧是真的跑的**。本机常见的现成 ffmpeg：RPA 工具（影刀 `D:\ShadowBot\*\ffmpeg.exe`）、剪映、OBS 目录。
> 交付时仍要说明"用了替身"，但可以明确界定：替身只提供路径，产出结果全真。

### 3. 完整闭环：把外部上游指向本地假服务

最有力的验证。以调用大模型为例：猴子补丁改掉上游地址，再起一个假服务记录**实际收到了什么**。

```python
# 假上游：记录收到的内容，返回合法结构
class FakeUpstream(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        content = body["messages"][0]["content"]
        info = {
            "model": body.get("model"),
            "auth": self.headers.get("Authorization", "")[:24],
            "image_count": sum(1 for c in content if c.get("type") == "image_url"),
            # 断言图片是真 base64 而不是空占位
            "valid": sum(1 for c in content if c.get("type") == "image_url"
                         and c["image_url"]["url"].startswith("data:image/")),
        }
        _received.update(info)                                   # 供断言
        payload = json.dumps({"choices":[{"message":{"content": json.dumps(FAKE_RESULT)}}]}).encode()
        ...  # 回 200

# 关键一行：把模块级常量指到本地
import app as app_mod
start_fake_upstream()
app_mod.API_URL = f"http://127.0.0.1:{PORT}/v1/chat/completions"
uvicorn.Server(uvicorn.Config(app_mod.app, host="127.0.0.1", port=APP_PORT)).run()
```

可断言的强证据：`上游收到的图片数 == 服务端记录的帧数`、`Authorization` 头格式正确、图片确实是合法 base64。
**注意**：假上游必须真的启动（别只在 `__main__` 分支里调 `start()`，`--selftest` 分支也要调）。

### 4. 修复前后对照实验（最有说服力）

同一套检查跑两个目录，用备份版本证明"漏洞真实存在"。

```python
PROJ = Path(os.environ.get("VI_PROJ")).resolve()   # 环境变量切换被测目录
sys.path.insert(0, str(PROJ)); os.chdir(PROJ)
```

- 路径穿越探针：`filename` 传**绝对路径**（Windows 上 `os.path.join(tmp, "C:/x")` 会丢弃 tmp，直接暴露是否逃逸），检查目标文件是否存在及字节数
- 框架桩要兼容新旧调用方式：上传对象同时实现 `async def read()` 和 `.file`

### 5. AST 静态检查（针对并发类修复）

检查所有 `async def` 端点体内是否直接调用已知阻塞函数：

```python
BLOCKING = {"download_video", "call_qwen", "extract_frames", "requests", "subprocess", "time.sleep"}
tree = ast.parse(Path("app.py").read_text(encoding="utf-8"))
for node in tree.body:
    if isinstance(node, ast.AsyncFunctionDef):
        for sub in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(sub, ast.Call) and _callee_name(sub.func) in BLOCKING:
                print(f"{node.name}() 第 {sub.lineno} 行阻塞调用")
```

`run_in_threadpool(extract_frames, ...)` 里的 `extract_frames` 是 `Name` 节点不是 `Call`，**天然不误报**——这就是这个检查好用的原因。

### 6. 网络策略类修改：注入「不可能成功的上游」

验证"不走代理 / 强制直连 / 禁用某上游"这类改动，**断言配置值没有意义**——要把上游指向必然失败的目标，用"请求还能不能成功"来判定。

```python
def free_port():                       # 绑一个空闲端口再释放 = 必然连不通
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

dead = f"http://127.0.0.1:{free_port()}/"
env.update({"HTTP_PROXY": dead, "HTTPS_PROXY": dead, "http_proxy": dead, "https_proxy": dead})
# 关键：必须删掉 NO_PROXY/no_proxy，否则 127.0.0.1 会被放行，实验当场失效
for k in ("NO_PROXY", "no_proxy"): env.pop(k, None)
```

判定：**请求仍成功 ⇒ 代理确实被绕过；请求失败 ⇒ 代理生效**。两侧都要跑——设 `VI_PROXY=dead` 时失败，才能证明"开关有效"而不是"永久禁用"。

要点：

- Windows 上 `requests` 的代理有**两个来源**：环境变量 **和** 注册表（`getproxies_environment() or getproxies_registry()`）。只删环境变量不够，必须 `Session.trust_env=False`
- 精确断言（比看行为更硬）：`session().merge_environment_settings(url, {}, None, None, None)["proxies"] == {}`
- **客户端脚本自身要免疫**（`trust_env=False` / `urllib` 的 `ProxyHandler({})`），否则客户端先挂，实验根本做不成
- 服务端要保留坏代理、客户端要绕过 —— 这两个需求 `NO_PROXY` 无法同时满足，只能让客户端从代码层免疫
- 断言别写 `"proxy" in k.lower()`：会命中平台注入的无关变量（如 `XXX_SERVICE_PROXY_URL`），造成假 FAIL



## 事件循环阻塞的机制验证

```python
async def run(analyze_fn, label):
    t0 = time.time()
    done = await asyncio.gather(analyze_fn(), status())
    print(f"{label}: analyze={done[0]-t0:.2f}s  status={done[1]-t0:.2f}s")
```

判定：status 本应 <0.01s；若等于阻塞时长，说明事件循环被独占。

HTTP 层的并发验证要用「N 个并发慢请求 + 独立线程计时」，避免请求到达顺序失真导致假结论。

## 装不上大依赖时怎么把真包装上

大 wheel（>20MB）常见现象：镜像 `/simple/` 索引页秒回，但文件下载龟速或 0 字节。

1. **别用 `-r 0-N` 测速**：部分镜像直接拒绝 Range 请求，会返回 0 B/s 让人误判"网络不通"；用普通请求 + `--max-time` 采样
2. 从 `/simple/<pkg>/` 页面取 wheel 直链（`grep -oE 'href="[^"]*\.whl[^"]*"'`）
3. `curl -L -C - --retry 5 --retry-all-errors` 后台断点续传，慢慢下
4. **装前校验 SHA256**（索引页的 `#sha256=` 就是期望值），比大小更可靠
5. 装时 `--no-deps` 避免拖累；wheel 文件名必须是规范的 `name-version-tags.whl`，改名会报 `Invalid wheel filename`

## 坑（本机实测）

- **系统代理**：`requests`/`httpx` 会继承 `HTTP_PROXY`，打本地 `127.0.0.1` 上游时报 `ProxyError`。应急可设 `NO_PROXY=127.0.0.1,localhost`，但**根治办法是在项目里集中收口**（清代理环境变量 + `trust_env=False` 会话 + 给 yt-dlp/curl_cffi 显式传 `proxy=""`），否则每次调试都要记得设、且 Windows 注册表代理删环境变量也拦不住
- **验证脚本自己要免疫代理**：服务端需要暴露在代理下做对照、客户端却必须绕过代理——用客户端的 `trust_env=False` 解决，别指望 `NO_PROXY`
- **Git Bash 的 `/tmp` 对 Windows 程序无效**：venv 里的 `python.exe` 不认 `/tmp/x.whl`（要 `cygpath -w`）；bash 里直接调 Windows 版 ffmpeg 传 `/tmp/...` 会报 `No such file or directory`
- **`import` 时求值的配置**（限额、访问码、开关）必须用**子进程**分别设环境变量再 import，同进程内改 env 无效
- **先跑项目自带的测试**：装上依赖后第一件事就跑 `test_*.py`——本次正是这样发现"自带测试里早有一个必然失败的断言"，暴露出一个真 bug
- **断言要匹配真实返回值类型**：把 base64 data URI 列表当文件路径去做 `os.path.exists()` 会全部落空，制造假 FAIL（本次踩过，浪费两轮）
- 沙箱里 pip 可能数分钟后被 SIGTERM 且无输出，别把方案押在装依赖上，先设计好桩路径
- 验证脚本放独立目录（`_verify/`），`PROJ` 用环境变量传入，可重复运行

## 交付时给出

1. 正向结果（N/N 通过），标明用的哪一层验证
2. 对照结果表（修复前 vs 修复后，带具体数字：字节数、处数、布尔值、耗时）
3. 明确列出未覆盖的部分与用到的替身（以及替身是否影响结论）
