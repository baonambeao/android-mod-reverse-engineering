---
date: "2026-04-22"
tags: ["Reverse Engineering", "Android", "ARM64", "Smali", "IDA Pro", "Cybersecurity"]

## Giai Đoạn 1: Dịch Ngược và Phân Tích Tầng Java/Smali

Mục tiêu đầu tiên là thấu hiểu cấu trúc của ứng dụng và xác định vị trí luồng xử lý xác thực.

### 1. Trích Xuất và Dịch Ngược APK
* **Công cụ sử dụng:** `apktool`
* **Thao tác:** Sử dụng lệnh `apktool d <tên-file.apk>` để dịch ngược gói APK gốc (`Minionscheats V3 VN 4.3 64Bit.apk`) thành mã Smali, các tệp kê khai XML và tài nguyên. Bước này cho phép kiểm tra mã nguồn tầng Java (đã được biên dịch thành Dalvik bytecode).

### 2. Xác Định Cơ Chế Xác Thực
* **Mục tiêu:** Tìm vị trí ứng dụng gửi thông tin cấp phép (User/Pass) đến máy chủ.
* **Phân tích:** Tiến hành tìm kiếm trong mã Smali với các từ khóa như `http`, `login`, và `Check`. Quá trình này giúp cô lập được lớp `com.rubel.kutta.Launcher`.
* **Luồng xử lý đã xác định:**
    1. Ứng dụng nhận chuỗi User/Pass từ giao diện người dùng.
    2. Gọi một hàm Native (C/C++) có tên `native_Check(String user, String pass)` nằm trong thư viện liên kết động `libKuttaVai.so`.
    3. Hàm Native này chịu trách nhiệm gửi yêu cầu mạng đến một máy chủ được mã hóa cứng (hardcoded) để xác thực khóa, sau đó trả về một chuỗi kết quả (ví dụ: `"OK"`).
    4. Tầng Java triển khai một Callback (`Launcher$100000003`) để nhận chuỗi này. Nếu chuỗi trả về khớp chính xác với `"OK"`, ứng dụng sẽ tiến hành khởi tạo Menu.

### 3. Can Thiệp Tầng Java (Patch Smali)
* **Thao tác ban đầu:** Chỉnh sửa mã Smali của lớp `Launcher$100000003`.
* **Sửa đổi:** Thay đổi điều kiện `if (result.equals("OK"))` thành một lệnh nhảy vô điều kiện (unconditional jump) luôn đánh giá là `True` (bỏ qua khối lệnh hiển thị lỗi chưa đăng ký).
* **Kết quả:** Giao diện Menu xuất hiện thành công. Tuy nhiên, các tính năng nội bộ (như ESP và Aimbot) hoàn toàn không hoạt động, đồng thời ứng dụng gặp hiện tượng crash (đóng băng/thoát đột ngột) liên tục.
* **Kết luận:** Lớp kiểm tra bảo mật chính không nằm ở tầng Java mà được nhúng sâu vào tầng Native (C/C++).

---

## Giai Đoạn 2: Phân Tích và Can Thiệp Tầng Native (C/C++)

Do bản vá lỗi ở tầng Java không mang lại hiệu quả toàn diện, bước tiếp theo là sử dụng **IDA Pro** để phân tích mã máy ARM64 của thư viện `libKuttaVai.so`.

### 1. Xử Lý Lỗi Crash Khi Khởi Tạo (SIGILL)
* **Vấn đề:** Ngay khi tải thư viện `.so` vào bộ nhớ, ứng dụng lập tức bị crash do lỗi tín hiệu SIGILL (Illegal Instruction).
* **Phân tích:** Nhật ký lỗi (`crash_log.txt`) chỉ đến địa chỉ `0x5f3470`. Hàm này nằm trong phân vùng `.init_array` (được thực thi tự động trước `JNI_OnLoad`). Nó chứa các cơ chế kiểm tra tính toàn vẹn của thư viện và cố tình gây ra lỗi nếu phát hiện bất kỳ sự thay đổi nào.
* **Giải pháp Patch:** Ghi đè toàn bộ hàm này bằng lệnh `RET` (Return), buộc hàm phải thoát ngay lập tức mà không thực thi các lệnh kiểm tra.
* **Mã Hex chèn vào:** `C0 03 5F D6` (Tương đương lệnh `RET` trong kiến trúc ARM64).

### 2. Phân Tích `native_Check` và Cờ "Master Switch"
* **Vấn đề:** Giao diện Menu đã hiển thị, nhưng tính năng ESP không thể render.
* **Phân tích:** Hàm `native_Check` (tại địa chỉ `0xF922C`) không chỉ xử lý giao tiếp mạng; nó hoạt động như một "Công tắc tổng" (Master Switch) cho toàn bộ hệ thống.
    * Khi nhận phản hồi thành công từ máy chủ, hàm sẽ ghi giá trị `1` vào một biến toàn cục `byte_B242A0`.
    * Sau đó, nó cấp phát bộ nhớ và điền dữ liệu cho hai biến Region Token tại `qword_B24150` và `qword_B24168`.
    * Tất cả các module chức năng (ESP, Aimbot) liên tục thăm dò biến `byte_B242A0`. Nếu giá trị vẫn là `0`, chúng sẽ ngừng hoạt động. Vì bản vá Smali ban đầu chỉ buộc tầng Java bỏ qua lỗi xác thực, tầng Native không bao giờ được khởi tạo đúng cách.

### 3. Vượt Qua Cơ Chế Anti-Tamper Của ESP (`memcmp`)
* **Phân tích Hàm Render ESP (`sub_E2004`):** Hàm này chứa một vòng lặp bảo mật. Nó liên tục sử dụng hàm `.memcmp` của hệ thống để so sánh đối chiếu từng byte của hai biến chuỗi Token `qword_B24150` và `qword_B24168`. Nếu hai chuỗi khác biệt (hoặc kích thước không chuẩn), quá trình render ESP bị hủy.
* **Chiến lược Bypass (Mô phỏng Token):** Thay vì dịch ngược thuật toán tạo Token phức tạp, giải pháp được chọn là "Mô phỏng" (Mocking).
    * Ép buộc kích thước của cả hai biến thành `8`.
    * Không cung cấp dữ liệu. Do đó, cả hai vùng nhớ chỉ chứa các byte NULL (`0x00`).
    * Khi hàm `.memcmp` so sánh hai chuỗi rỗng có cùng kích thước, nó sẽ trả về `0` (Khớp tuyệt đối). Cách này qua mặt vòng lặp anti-tamper thành công.

### 4. Viết Lại Hàm `native_Check` (Bằng Assembly)
Kết hợp các phân tích trên, đoạn mã máy ARM64 mới được chèn trực tiếp vào điểm bắt đầu (entry point) của hàm `native_Check` (tại `0xF922C`):

```assembly
# 1. Kích hoạt Master Switch (byte_B242A0 = 1)
MOV W10, #1
ADRP X9, 0xB242A0
ADD X9, X9, 0x2A0
STRB W10, [X9]

# 2. Mô phỏng Token 1 (Kích thước = 8, nội dung = NULL)
ADRP X9, 0xB24150
ADD X9, X9, 0x150
MOV W10, #8
STRB W10, [X9]

# 3. Mô phỏng Token 2 (Kích thước = 8, nội dung = NULL)
ADRP X9, 0xB24168
ADD X9, X9, 0x168
STRB W10, [X9]

# 4. Trả về chuỗi "OK" cho tầng Java
# (Sử dụng con trỏ JNIEnv để gọi NewStringUTF)
LDR X8, [X0]           # Lấy con trỏ JNIEnv*
ADRP X1, 0x304000      # Trỏ tới địa chỉ chứa chuỗi "OK\0"
ADD X1, X1, 0xF00
LDR X8, [X8, 0x538]    # Nạp con trỏ hàm NewStringUTF từ JNIEnv
BR X8                  # Rẽ nhánh tới hàm và trả kết quả
