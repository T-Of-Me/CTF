# The Trial - LA CTF 2026 Writeup

**Category:** Web
**Challenge URL:** https://the-trial.chall.lac.tf/
**Flag:** `lactf{gregor_samsa_awoke_from_wait_thats_the_wrong_book}`

---

## Overview

Challenge mô phỏng một trang web theo theme "The Trial" (Franz Kafka) - yêu cầu điền đúng từ vào câu **"I want the ____."** rồi POST lên server để lấy flag.

---

## Step 1: Khảo sát giao diện

Truy cập https://the-trial.chall.lac.tf/ ta thấy:

- Tiêu đề **"The Trial"**
- Dòng chữ: *"Want the flag? Just fill in the sentence and we'll send it right over."*
- Câu cần điền: **"I want the ____."**
- Một **range slider** xoay liên tục (animation spin 360 độ)
- Nút **Submit** và **I'm Feeling Lucky** nhảy lung tung trên màn hình (bounce animation)

Giao diện được thiết kế để **cản trở** người dùng thao tác bình thường - slider xoay, nút chạy khắp nơi.

## Step 2: Phân tích source code

View source trang web, tập trung vào phần JavaScript:

```javascript
const cm = "kjzhcyprdolnbgusfiawtqmxev";

function update() {
    let s = "";
    let n = val.value;
    for (let i = 0; i < 4; i++) {
        s += cm[n % cm.length];
        n = Math.floor(n / cm.length);
    }
    if (disp.textContent !== s) {
        disp.textContent = s;
    }
}

submit.addEventListener("click", async () => {
    const req = await fetch("/getflag", {
        method: "POST",
        body: `word=${encodeURIComponent(disp.textContent)}`,
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        }
    });
    msg.textContent = await req.text();
});
```

### Phân tích:

1. **Slider** có range `0 - 456975` (= 26^4 - 1), tức là cover toàn bộ tổ hợp 4 ký tự
2. Giá trị slider được **chuyển đổi** thành chuỗi 4 ký tự thông qua cipher map `"kjzhcyprdolnbgusfiawtqmxev"`
3. Khi nhấn Submit, nó POST đến endpoint `/getflag` với parameter **`word=`** (KHÔNG phải `answer=`)
4. Nút "I'm Feeling Lucky" chỉ rickroll (redirect YouTube)

## Step 3: Xác định từ cần gửi

Câu hỏi là "I want the ____." - đáp án hiển nhiên nhất là **"flag"**.

Mặc dù slider encode từ qua cipher, server nhận chuỗi 4 ký tự đã được hiển thị trên giao diện. Vậy ta chỉ cần gửi trực tiếp từ `flag`.

## Step 4: Gửi request lấy flag

Bypass hoàn toàn giao diện troll, gửi thẳng bằng curl:

```bash
curl -s -X POST https://the-trial.chall.lac.tf/getflag \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "word=flag"
```

**Response:**
```
Ah, you want the flag? Well here you go! lactf{gregor_samsa_awoke_from_wait_thats_the_wrong_book}
```

---

## Sai lầm thường gặp

| Sai | Đúng |
|-----|------|
| Parameter `answer=` | Parameter `word=` |
| Gửi đến `/` | Gửi đến `/getflag` |
| Cố dùng slider trên giao diện | Bypass bằng curl/script |
| Thử prompt injection (tưởng là LLM challenge) | Đọc source JS để hiểu logic |

---

## Takeaway

- **Luôn đọc source code** trước khi thử payload bừa
- Chú ý tên parameter trong JavaScript (`word` chứ không phải `answer`)
- Đáp án đơn giản nhưng giao diện được thiết kế để đánh lạc hướng (Kafka-style bureaucracy)
- Flag reference: *"Gregor Samsa awoke"* là mở đầu truyện **"The Metamorphosis"** của Kafka, không phải "The Trial" - đúng như flag nói: *"wait that's the wrong book"*
