# 打開一個 repo 之前先掃一遍：preflight 是怎麼運作的

*一個假的招募者寄給你一份面試作業。你把它 clone 下來、用 VS Code 打開、按下「是，我信任作者」，然後在你讀到第一行程式碼之前，後門就已經裝好了。這篇文章講這個攻擊、講為什麼現有的建議只停在「小心一點」，以及我怎麼做出一個**完全不執行目標 repo** 就能抓到這個機制的靜態掃描器。*

（English version: [writeup.md](writeup.md)）

---

## 1. 攻擊本身

從 2023 年開始，一群與北韓有關的行動——被追蹤為 **Contagious Interview**（也叫 DeceptiveDevelopment、Void Dokkaebi）——以工作機會為餌鎖定軟體開發者。誘餌很平凡：一個招募者、一間看起來像樣的公司，還有一份用 Git repo 交付的程式作業。真正的 payload 不在他們請你寫的程式碼裡，而在它周圍的「管線」裡。

Microsoft、Trend Micro、GitLab 等整理過的各種變體，形狀都一樣：

1. **一個不經思考就會觸發的觸發點。** 最有效的是 `.vscode/tasks.json` 裡設定 `"runOn": "folderOpen"` 的 VS Code task。當你打開資料夾、接受 Workspace Trust 提示（每個開發者都會按，因為不按什麼都不能動），這個 task 就執行了。其他觸發點：`package.json` 的 `postinstall`、`devcontainer.json` 的 `initializeCommand`（在你的**主機**上執行，不是在容器裡）、`setup.py`、`.envrc`，以及近來 `.claude/settings.json` 裡的 hooks。
2. **一個不像 payload 的 payload。** 一個存成 `fa-solid-900.woff2`、放在字型資料夾裡的 JavaScript 檔。一個真正的內容從第 300 欄才開始、超出任何編輯器可視範圍的設定檔。`eval(Buffer.from("...", "base64"))`。向 `api.npoint.io` 或一個裸 IP 發出 fetch，再接 `new Function(body)()`。
3. **第二階段**，由前面的 stager 下載下來：竊取憑證（瀏覽器設定檔、SSH 金鑰、雲端憑證、加密貨幣錢包），以及一個常駐後門。

每一份廠商報告給的建議都是某種版本的「信任 workspace 之前先檢查 `tasks.json`」和「用 VM 打開不明的 repo」。這是對的，但沒有人會做。我想要一個把這個檢查變成**一行指令**的工具。

## 2. 三個設計原則

有三個決定形塑了其他所有東西。

**絕不執行目標。** 這聽起來理所當然，直到你注意到有多少「掃描器」會跑 `npm install` 來解析相依、或跑 `git status` 來列檔案。一個惡意 repo 自己的 `.git/config` 可以定義 `core.fsmonitor` 指令，所以連 `git status` 都是程式執行。preflight 只走訪檔案系統、用大小上限讀檔、記錄 symlink 但絕不跟隨、用自己寫的 JSONC parser 解析設定。`clone` 子指令跑 `git clone` 時帶 `--no-recurse-submodules`、`core.hooksPath=/dev/null`、`protocol.ext.allow=never`、`protocol.file.allow=never`，並關閉 LFS smudging。

**零相依。** 一個檢查供應鏈攻擊的工具，自己不該變成供應鏈風險。preflight 只用 Go 標準庫，發佈成單一靜態執行檔，附帶簽章過的 build provenance。

**解釋觸發點，而不只是「聞起來怪」。** 每一條發現都會說明：要讓這段程式碼執行，**你**得做什麼——「用 VS Code 打開資料夾」、「安裝相依套件」、「啟動 AI coding agent」。沒有觸發點的發現只是內容上的可疑；有觸發點的發現才是威脅。

## 3. 觸發點 × 內容 → 鏈

核心想法很小。偵測器分成兩類：

- **觸發點偵測器**解析設定，記錄**哪些檔案會被執行**。`tasks.json` → 指令的參數；`package.json` → `postinstall`，以及（因為面試作業一定會叫你「跑 `npm start`」）`start` 和 `test` 腳本；`devcontainer.json` → 生命週期指令；`.claude/settings.json` → hook 指令；`.mcp.json` → server 指令。指令列會被 tokenize，`${workspaceFolder}`、`$CLAUDE_PROJECT_DIR` 這類變數被剝掉，每個 token 再照 Node 和 shell 的方式解析（`server` → `server.js` → `server/index.js`，v0.2.0 之後也涵蓋 `.py` / `.sh` / `.mjs` 等）。
- **內容偵測器**只看檔案內容、不管它怎麼被觸發：副檔名宣稱是字型但其實是腳本（用 magic bytes 判斷）、在 150 個以上空白之後才出現的程式碼、同一行內 decode 再 eval、在 1,500 bytes 內「下載再 eval」、看不見的 Unicode Tag 字元（會解碼出來給你看）、Trojan Source 的雙向控制字元、指向 paste 網站的連結。

單獨來看，這些大多很弱。GitHub 上最熱門的 repo 有 22% 有安裝腳本；有 14% 在某處出現 `atob` 緊鄰 `Function(`，通常是在打包過的 module loader 裡。**罕見的是「組合」**：一個觸發點，它解析出來的目標檔案剛好帶有內容訊號。這就是 `PF001 auto-exec-chain` 規則，也是整個掃描器裡我唯一願意稱之為「偵測」而非「啟發式猜測」的東西：

```
[CRITICAL] .vscode/tasks.json:6  PF001 auto-exec-chain
           Opening the folder in VS Code executes public/fonts/fa-solid-900.woff2,
           which contains: disguised-file, decode-and-execute
```

自動觸發點背後的鏈是 critical。使用者自己打的指令（`npm start`）背後的鏈是 high，而且要求內容發現本身是 high 等級——因為一個對帶有長 base64 字串的檔案跑 `tsc` 的 build 腳本並不是攻擊。

## 4. 不被雜訊淹沒的評分

早期版本是把各發現的權重相加。一個文件很多、含 300 個零寬空白的 repo，分數會跟一個有 300 個問題的 repo 一樣高。兩個改動修正了這點：

- 同一條規則最多只有 **3 筆**計入分數。
- 判定邏輯：有任何 critical 就 `DANGER`；有任何 high、或分數達到 50（三條不同的 medium 規則各達上限）就 `REVIEW`；否則 `CLEAN`。low 和 informational 的發現會顯示，但從不改變判定。

## 5. 1,000 個熱門 repo 的基準測試，以及它教我的事

我掃了 **GitHub 上星數最高的 1,000 個 repo**，把它們當成良性。第一次跑是 73% CLEAN。五輪調整後變成 **92.8% CLEAN、6.9% REVIEW、0.3% DANGER**，而且完全沒動到鏈規則。那些「錯的」比「對的」更有意思：

1. **Git LFS 指標檔。** 因為加固過的 clone 關閉了 LFS smudging，每個用 LFS 追蹤的圖片都變成一個 130 bytes 的文字檔、佔在 PNG 該在的位置。magic-byte 檢查在 52 個 repo 把它們標成「偽裝成圖片的腳本」。現在掃描器認得這個指標檔格式了。
2. **🏴󠁧󠁢󠁥󠁮󠁧󠁿 是用 Unicode Tag 字元組成的。** 英格蘭、蘇格蘭、威爾斯的旗幟 emoji，編碼方式是 🏴 後面接 Tag 字母再接一個 cancel tag。任何 emoji 資料集都會點亮一個 critical 的「tag 走私」發現。現在跟在 U+1F3F4 後面的 Tag 會被跳過，嚴重度則看隱藏文字解碼出來是什麼：真正的指令有空白，`gbenggbsctgbwls` 沒有。
3. **`RegExp.exec()` 不是 `exec()`。** 我的「動態執行」regex 原本會命中 `csrfRegex.exec(response)`、`cdp.eval(...)`、`def eval(self)`、以及註解裡的 `eval()`。現在它要求參數是變數、前面不能是 `.`，並跳過註解行。
4. **minified 的程式碼長得像惡意程式。** `(globalThis.TURBOPACK||[]).push(...` 配上同一行 40 KB 裡的 `atob` 和 `Function`，是每一個 Next.js build。現在用「行的密度」判斷是不是產生出來的程式碼，而不只是看它是否住在 `dist/` 底下。
5. **熱門專案會設定自己的 agent。** 前 1,000 名裡有 3.8% 內含 Claude Code hooks、3.9% 內含 MCP server。在你信任的 repo 裡它們是便利功能；在陌生人給你的 repo 裡它們就是攻擊面。現在它們是 medium 發現，只有當它們執行的腳本本身可疑時，才由鏈規則升級。
6. **世界上有從右到左的語言。** 阿拉伯文、烏爾都文的翻譯檔會合理地使用雙向控制字元。Trojan Source 只有在人會審閱的原始碼裡才要緊，所以嚴重度現在看路徑和檔案類型。

剩下的三個 `DANGER` 全都是這個機制的真實案例：`microsoft/vscode` 有一個 Copilot extension 的 task 真的會在打開資料夾時執行；一個大學課程封存裡有一個被改名成 `.zip` 的 `.exe`；`big-list-of-naughty-strings` 真的內嵌了 Unicode Tag 字元。我認為這三個是對的。

## 6. 讓它被獨立評估：一個會讓核心保證失效的 DoS

寫完工具、跑完基準測試之後，我請三個獨立的角度各自評估它：一個紅隊視角找覆蓋缺口、一個第一次使用者找體驗問題、一個資深工程師做程式碼審查與新穎度比較。這一步比我預期的更有價值——因為**對的東西是我已經知道的，錯的東西才是我該知道的**。

最重要的一個發現打在工具的核心主張上：

> preflight 宣稱「能安全地讀取攻擊者控制的位元組」。但內容掃描有一個 CPU 耗盡的 DoS：對每一行符合動態 eval 的程式碼，它都會切出一個 ~3 KB 的視窗、在上面跑那個很重的 network regex。如果一個檔案裡有很多 eval、但附近始終沒有網路呼叫，就會變成 O(行數 × 視窗 × 大 regex)，而且沒有提早結束。

審查者實測：一個 4 MB、每行都是 `eval(atob('x'))` 但沒有網路呼叫的檔案，會讓掃描卡住超過 40 秒、被 kill。一個惡意 repo 可以放上 20 萬個這種檔案，輕鬆癱瘓 CI。這正好戳破「安全讀取攻擊者的位元組」這句話。

修法很乾淨：把 network regex 的比對從「逐行」提到「整檔跑一次」，之後逐行只做一個廉價的鄰近性檢查。同一個 4 MB 檔案從 >40 秒降到約 2 秒。

另外兩個方向一致的發現也補掉了：

- **鏈式解析原本只認 Node。** 一個 folderOpen task 若執行 `python helper.py` 或一個 `.sh` / `.mjs` payload，招牌的 PF001 鏈不會成立——儘管 README 的威脅模型明明宣傳支援 Python/shell。紅隊和程式碼審查**各自獨立**指出了這點。現在解析涵蓋 `.py/.sh/.ts/.mjs/.cjs` 等。
- **內容折扣被套用到觸發點會執行的檔案上。** payload 放進 `dist/` 或 `tests/` 就會被降級、鏈斷掉，一個混淆過的 `postinstall` stager 因此可能被判成 CLEAN。現在先跑觸發點偵測、收集被執行的檔案清單，content 偵測對這些檔案跳過 bundled / test 折扣。

這些修正（v0.2.0）帶來一個我很滿意的結果：**偵測變強，而 1,000 個 repo 的基準測試數字完全沒變**——同樣 92.8% CLEAN、同樣 3 個 DANGER、零新增誤判。原因很合理：這些更嚴格的規則只在「觸發點真的執行某個檔案、而該檔案又帶有 payload 訊號」時才生效，這在良性 repo 幾乎不會發生。

對我來說，這段過程本身就是結論的一部分：一個資安工具的價值，不只在於它一開始能抓到什麼，更在於它經得起被人認真地找碴。

## 7. 它不做什麼

preflight 找的是**自動、或在第一個明顯指令下**會執行的程式碼。它不是惡意程式掃描器、不解析相依、而且有決心的攻擊者可以繞過字串層的啟發式判斷。`CLEAN` 的意思是「沒有已知的自動執行向量」，面對不明的 repo，正確的做法仍然是用 VM 或 Codespace 的 Restricted Mode 打開。這個工具的工作，是確保你在按下「信任」**之前**就知道情況。

## 8. 使用

```bash
go install github.com/howardhsieh/preflight/cmd/preflight@latest
preflight clone https://github.com/someone/interview-task   # 加固過的 clone + 掃描
preflight scan . -f sarif -o preflight.sarif                # 給 GitHub code scanning
```

或作為 GitHub Action，`howardhsieh/preflight@v0.2.0`：它會在執行前先驗證 release 的 checksum，並輸出 `verdict` 和 `score`。

原始碼、規則清單和基準測試都在
[github.com/howardhsieh/preflight](https://github.com/howardhsieh/preflight)。

---

*參考資料：Microsoft Threat Intelligence 關於 `tasks.json` 濫用的分析；GitLab,
"How to detect and prevent Contagious Interview IDE attacks"；Trend Micro 關於 Void
Dokkaebi 的報告；Cloud Security Alliance 關於 AI skills 中 Unicode 指令注入的研究；
Boucher & Anderson, "Trojan Source" (2021)。*
