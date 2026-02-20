# kd - Forensics

## Challenge

> something crashed. something was left behind.

**Flag format:** `0xfun{}`

**Files:** `config.dat`, `crypter.dmp`, `events.xml`, `transcript.enc`

## Analysis

### Nhận diện file

| File | Mô tả |
|------|--------|
| `events.xml` | Windows Event Log (XML) - ghi lại hoạt động của `CrypterService` |
| `crypter.dmp` | Windows Minidump (MDMP) - crash dump của `crypter.exe` |
| `config.dat` | Binary data - config đã mã hóa |
| `transcript.enc` | Encrypted transcript - header ghi `IR-CASE-2026-0211 | CrypterService crash` |

### Event Log

`events.xml` chứa ~7400 dòng Windows Event, ghi lại timeline của `CrypterService`:

- **Boot** - Hệ thống khởi động
- **CrypterService** khởi chạy với các operation: `KeyNegotiation`, `KeyRotation`, `KeyDerivation`
- Nhiều `SessionToken` được tạo ra qua các lần rotate key
- **APPCRASH** - `crypter.exe` crash nhiều lần (Event: `Microsoft-Windows-WER-SystemErrorReporting`)

```xml
<Data Name="Message">Fault bucket type 0. Event: APPCRASH. App: crypter.exe</Data>
```

Hint rõ ràng: **"something crashed"** = `crypter.exe` crash, **"something was left behind"** = crash dump file.

### Crash Dump

`crypter.dmp` là file Windows Minidump (~425MB), header `MDMP`. Khi process crash, Windows tự động dump toàn bộ memory của process ra file. Nếu flag nằm trong memory tại thời điểm crash, nó sẽ bị capture luôn trong dump.

## Solution

Tên challenge **"kd"** gợi ý đến **WinDbg/kd** (kernel debugger), nhưng thực tế chỉ cần tìm string trong crash dump.

Search string `0xfun` trong file `crypter.dmp`:

```python
with open('crypter.dmp', 'rb') as f:
    dmp = f.read()

idx = dmp.find(b'0xfun')
print(dmp[idx:idx+60])
```

```
b'0xfun{wh0_n33ds_sl33p_wh3n_y0u_h4v3_cr4sh_dumps}\x00'
```

Hoặc đơn giản hơn với `strings` (Linux):

```bash
strings crypter.dmp | grep "0xfun"
```

## Flag

```
0xfun{wh0_n33ds_sl33p_wh3n_y0u_h4v3_cr4sh_dumps}
```
