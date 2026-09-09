# I2C Transaction Analyzer

Parses and groups raw I2C frames into transactions, handling each ACK/NACK, repeated START condition and idle time.

## 🚀 Features

- **Transaction Grouping**: Combines raw I2C low-level analyzer frames (Start, Address, Data, Stop) into clean, logical transactions.
- **Repeated START Support**: Detects and indicates repeated START conditions.
- **Write-then-Read (WTR) Support**: Detects Write-then-Read sequences (a Write transaction immediately followed by a matching Read transaction to the same address) and displays them combined in a single row.
- **ACK/NACK Tracking**: Captures and records ACK/NACK states (`(A)` / `(N)`) for both addresses and data payloads.
- **Precise Timing Metrics**:
  - **Idle Time**: Measures the gap from the *previous transaction's STOP* to the *current transaction's START* (`idle_time_us`) to accurately evaluate device-specific intervals.
- **Local Time Conversion**: Converts internal Saleae timestamps into your PC's local time zone (e.g., Japan Standard Time).
- **Address Filtering**: Easily exclude unneeded traffic by specifying an I2C address (e.g., `0x50`) in the analyzer settings.

---

## 📋 Analyzer Settings

| Setting Label | Type | Description |
| :--- | :--- | :--- |
| **Exclude Addresses** | String | Specify one or more I2C addresses to exclude from the output log, separated by commas (e.g., `0x50, 0x60`). |

---

## 📊 Output Data Fields

The analyzer outputs a structured set of fields for each transaction:

1. **`01_start_time`**: Local timestamp at the start of the transaction (YYYY-MM-DD HH:MM:SS.ffffff)
2. **`02_stop_time`**: Local timestamp at the end of the transaction
3. **`03_duration_us`**: Duration of the transaction in microseconds
4. **`04_idle_time_us`**: Time elapsed from the previous STOP to the current START in microseconds
5. **`05_is_repeated_START`**: Indicates if the primary operation started with a repeated START (`Y` or empty)
6. **`06_addr`**: Primary I2C target address (Hex)
7. **`07_rw_mode`**: Primary operation mode (`W` for Write, `R` for Read)
8. **`08_addr_ack`**: ACK/NACK status for the primary address (`(A)` or `(N)`)
9. **`09_payload`**: Data payload bytes with individual ACK/NACK states for the primary operation
10. **`10_has_write_then_read(WTR)`**: Indicates whether the Write transaction is followed by a Read transaction to the same I2C address (`Y` or empty)
11. **`11_WTR_is_repeated_START`**: Indicates if the WTR Read operation started with a repeated START (`Y` or empty)
12. **`12_WTR_addr`**: Target address for the WTR Read segment
13. **`13_WTR_rw_mode`**: Operation mode for the WTR segment (`R`)
14. **`14_WTR_addr_ack`**: ACK/NACK status for the WTR address
15. **`15_WTR_payload`**: Data payload bytes for the WTR Read segment

> ⚠️ **Note on Column Order in Logic 2:**
> Due to a known issue in Saleae Logic 2, data table columns may not always appear in the exact numerical order (`01_`, `02_`, etc.) defined by extensions. The order can occasionally vary depending on when fields are first encountered in the capture, and this behavior cannot be controlled from the extension side.
> 
---
